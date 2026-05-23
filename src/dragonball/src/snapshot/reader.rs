// Copyright (C) 2025 Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Snapshot blob reader (planning-repo ADR-0003, I-007).
//!
//! Phase 1 reader: parses the ATEOMSN1 v2 format into in-memory structs.
//! Memory payloads are streamed via a callback so the caller can write them
//! straight into guest memory without materializing all 256 MiB at once.

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use super::metadata::{MAGIC, MAGIC_TRAILER, SNAPSHOT_FORMAT_VERSION};
use super::vcpu_state::VcpuStateData;
use super::{MemoryRegionDescriptor, SnapshotError};

/// Parsed header + vCPU state. Memory payloads are NOT loaded eagerly; the
/// caller drives them via [`SnapshotReader::for_each_region`].
#[derive(Debug)]
pub struct SnapshotReader {
    reader: BufReader<File>,
    /// `format_version` from the header.
    pub format_version: u32,
    /// Number of vCPU states recorded in this snapshot.
    pub vcpu_count: u8,
    /// Total guest RAM size in bytes.
    pub mem_size_bytes: u64,
    /// Captured vCPU register snapshots (already consumed from the stream).
    pub vcpu_states: Vec<VcpuStateData>,
    /// Memory region descriptor table.
    pub regions: Vec<MemoryRegionDescriptor>,
    /// Cursor position after the region descriptor table; the body of
    /// `for_each_region` starts here.
    region_index: usize,
}

impl SnapshotReader {
    /// Open and parse the snapshot at `path`, leaving the reader positioned
    /// just before the first region's payload bytes.
    pub fn open(path: &Path) -> Result<Self, SnapshotError> {
        let file = File::open(path)?;
        let mut r = BufReader::new(file);

        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(SnapshotError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad snapshot magic: {magic:?}"),
            )));
        }

        let format_version = read_u32(&mut r)?;
        if format_version != SNAPSHOT_FORMAT_VERSION {
            return Err(SnapshotError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported snapshot format version {format_version}, expected {SNAPSHOT_FORMAT_VERSION}"
                ),
            )));
        }
        let vcpu_count = read_u8(&mut r)?;
        let _reserved_u8 = read_u8(&mut r)?;
        let _reserved_u16 = read_u16(&mut r)?;
        let mem_size_bytes = read_u64(&mut r)?;

        let mut vcpu_states = Vec::with_capacity(vcpu_count as usize);
        for _ in 0..vcpu_count {
            let vcpu_id = read_u8(&mut r)?;
            let regs = read_len_prefixed(&mut r)?;
            let sregs = read_len_prefixed(&mut r)?;
            let msrs = read_len_prefixed(&mut r)?;
            let cpuid_entries = read_len_prefixed(&mut r)?;
            vcpu_states.push(VcpuStateData {
                vcpu_id,
                regs,
                sregs,
                msrs,
                cpuid_entries,
            });
        }

        let region_count = read_u32(&mut r)?;
        let mut regions = Vec::with_capacity(region_count as usize);
        // We need to read descriptors but NOT payload yet — payload follows
        // each descriptor inline per format v2. So loop region-at-a-time and
        // remember to drive `for_each_region` immediately after.
        // Simpler: parse all descriptors-and-skip-payload here would require
        // seeking. Instead expose `for_each_region` that does the
        // interleaved read in order.
        //
        // To allow callers to inspect descriptors first, we read the first
        // descriptor here and stash the rest behind a state-machine cursor.
        // BUT — for Phase 1 the descriptor table is always 1 entry, so we
        // read it eagerly and let `for_each_region` consume the payload.
        for _ in 0..region_count {
            let guest_phys_addr = read_u64(&mut r)?;
            let size = read_u64(&mut r)?;
            let payload_len = read_u64(&mut r)?;
            if payload_len != size {
                return Err(SnapshotError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Phase 1 expects payload_len == size; got {payload_len} vs {size}"
                    ),
                )));
            }
            regions.push(MemoryRegionDescriptor {
                guest_phys_addr,
                size,
            });
            // NOTE: cannot eagerly skip payload here because the caller
            // wants to consume it next. Bail out of the descriptor loop
            // after the first; restart of descriptors-after-payload-N
            // would require seeking. Phase 1 has exactly one region so
            // this simplification is fine — assert.
            break;
        }
        if region_count != 1 {
            return Err(SnapshotError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Phase 1 reader supports exactly one region, got {region_count}"),
            )));
        }

        Ok(SnapshotReader {
            reader: r,
            format_version,
            vcpu_count,
            mem_size_bytes,
            vcpu_states,
            regions,
            region_index: 0,
        })
    }

    /// Stream the next region's memory payload into `sink`.
    ///
    /// Returns the descriptor of the region just streamed. Callers should
    /// loop while `region_index < regions.len()`.
    pub fn read_next_region<S>(
        &mut self,
        mut sink: S,
    ) -> Result<MemoryRegionDescriptor, SnapshotError>
    where
        S: FnMut(&[u8]) -> Result<(), SnapshotError>,
    {
        if self.region_index >= self.regions.len() {
            return Err(SnapshotError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "no more regions to read",
            )));
        }
        let desc = self.regions[self.region_index];
        let mut remaining = desc.size as usize;
        let mut buf = vec![0u8; 1 << 20]; // 1 MiB chunks.
        while remaining > 0 {
            let take = remaining.min(buf.len());
            self.reader.read_exact(&mut buf[..take])?;
            sink(&buf[..take])?;
            remaining -= take;
        }
        self.region_index += 1;
        Ok(desc)
    }

    /// Verify the trailer is present at the current stream position.
    pub fn check_trailer(&mut self) -> Result<(), SnapshotError> {
        let mut trailer = [0u8; 4];
        self.reader.read_exact(&mut trailer)?;
        if trailer != MAGIC_TRAILER {
            return Err(SnapshotError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad snapshot trailer: {trailer:?}"),
            )));
        }
        Ok(())
    }
}

fn read_u8<R: Read>(r: &mut R) -> io::Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}
fn read_u16<R: Read>(r: &mut R) -> io::Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}
fn read_u32<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}
fn read_u64<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}
fn read_len_prefixed<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let len = read_u32(r)? as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}
