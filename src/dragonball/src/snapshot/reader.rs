// Copyright (C) 2025 Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Snapshot blob reader (planning-repo ADR-0003, I-007 / I-008a).
//!
//! v3 reader: parses the ATEOMSN1 v3 format. Header carries an absolute
//! page-aligned `file_offset` per memory region so the caller can either
//! stream the payload via [`SnapshotReader::read_next_region`] (Phase-1
//! restore) **or** `mmap(MAP_PRIVATE, snap_fd, file_offset, size)` it
//! directly over guest memory (I-008a mmap overlay).

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use super::metadata::{SnapshotKind, MAGIC, MAGIC_TRAILER, SNAPSHOT_FORMAT_VERSION};
use super::serial_state::LegacyDeviceState;
use super::vcpu_state::VcpuStateData;
use super::virtio_net_state::{self, VirtioNetState};
use super::vm_state::VmStateData;
use super::{MemoryRegionDescriptor, SnapshotError};

/// Descriptor enriched with the absolute file offset where the region's
/// payload lives. Used by the mmap restore fast path.
#[derive(Debug, Clone, Copy)]
pub struct RegionLocation {
    /// Guest physical address of the region.
    pub guest_phys_addr: u64,
    /// Region size in bytes.
    pub size: u64,
    /// Absolute, page-aligned byte offset of the region payload inside
    /// the snapshot file.
    pub file_offset: u64,
}

impl From<RegionLocation> for MemoryRegionDescriptor {
    fn from(loc: RegionLocation) -> Self {
        MemoryRegionDescriptor {
            guest_phys_addr: loc.guest_phys_addr,
            size: loc.size,
        }
    }
}

/// Parsed header + vCPU state. Memory payloads are NOT loaded eagerly; the
/// caller drives them either via [`SnapshotReader::read_next_region`]
/// (streamed copy) or [`SnapshotReader::regions_for_mmap`] +
/// [`SnapshotReader::raw_fd`] (mmap-overlay fast path).
#[derive(Debug)]
pub struct SnapshotReader {
    reader: BufReader<File>,
    /// Path the snapshot was opened from (informational).
    pub path: PathBuf,
    /// `format_version` from the header.
    pub format_version: u32,
    /// `snapshot_kind` from the v9 header (Golden or Diff).
    pub kind: SnapshotKind,
    /// Number of vCPU states recorded in this snapshot.
    pub vcpu_count: u8,
    /// Total guest RAM size in bytes.
    pub mem_size_bytes: u64,
    /// `parent_sha256` from the v9 header. All-zero for Golden;
    /// SHA-256 of the parent golden file for Diff (audit I-004 §4 Q2).
    pub parent_sha256: [u8; 32],
    /// Captured vCPU register snapshots (already consumed from the stream).
    pub vcpu_states: Vec<VcpuStateData>,
    /// Captured VM-level architectural state (v4+).
    pub vm_state: VmStateData,
    /// Captured legacy-device state (v6+).
    pub legacy_state: LegacyDeviceState,
    /// Captured virtio-net device state envelope (v7+).
    pub virtio_net_state: VirtioNetState,
    /// Memory region descriptor table — guest addr + size only.
    pub regions: Vec<MemoryRegionDescriptor>,
    /// Per-region absolute file offsets (parallel to `regions`).
    pub region_offsets: Vec<u64>,
    /// Index of next region to stream via [`Self::read_next_region`].
    region_index: usize,
}

impl SnapshotReader {
    /// Open and parse the snapshot at `path`, leaving the reader positioned
    /// at the start of the first region payload's page-aligned slot.
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
        let kind_byte = read_u8(&mut r)?;
        let kind = SnapshotKind::from_u8(kind_byte).ok_or_else(|| {
            SnapshotError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown snapshot_kind byte {kind_byte} in v9 header"),
            ))
        })?;
        let _reserved_u16 = read_u16(&mut r)?;
        let mem_size_bytes = read_u64(&mut r)?;
        let mut parent_sha256 = [0u8; 32];
        r.read_exact(&mut parent_sha256)?;
        match kind {
            SnapshotKind::Golden => {
                if parent_sha256 != [0u8; 32] {
                    return Err(SnapshotError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Golden snapshot must have all-zero parent_sha256",
                    )));
                }
            }
            SnapshotKind::Diff => {
                if parent_sha256 == [0u8; 32] {
                    return Err(SnapshotError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Diff snapshot must carry a non-zero parent_sha256",
                    )));
                }
            }
        }

        let mut vcpu_states = Vec::with_capacity(vcpu_count as usize);
        for _ in 0..vcpu_count {
            let vcpu_id = read_u8(&mut r)?;
            let regs = read_len_prefixed(&mut r)?;
            let sregs = read_len_prefixed(&mut r)?;
            let msrs = read_len_prefixed(&mut r)?;
            let cpuid_entries = read_len_prefixed(&mut r)?;
            let lapic = read_len_prefixed(&mut r)?;
            let xsave = read_len_prefixed(&mut r)?;
            let vcpu_events = read_len_prefixed(&mut r)?;
            let mp_state = read_len_prefixed(&mut r)?;
            let xcrs = read_len_prefixed(&mut r)?;
            vcpu_states.push(VcpuStateData {
                vcpu_id,
                regs,
                sregs,
                msrs,
                cpuid_entries,
                lapic,
                xsave,
                vcpu_events,
                mp_state,
                xcrs,
            });
        }

        let region_count = read_u32(&mut r)?;
        let mut regions = Vec::with_capacity(region_count as usize);
        let mut region_offsets = Vec::with_capacity(region_count as usize);
        for _ in 0..region_count {
            let guest_phys_addr = read_u64(&mut r)?;
            let size = read_u64(&mut r)?;
            let file_offset = read_u64(&mut r)?;
            if file_offset % 4096 != 0 {
                return Err(SnapshotError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("region file_offset {file_offset} is not 4 KiB aligned"),
                )));
            }
            regions.push(MemoryRegionDescriptor {
                guest_phys_addr,
                size,
            });
            region_offsets.push(file_offset);
        }
        // Phase 1 / I-008a still expects exactly one region; I-008b widens.
        if region_count != 1 {
            return Err(SnapshotError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Phase 1 reader supports exactly one region, got {region_count}"),
            )));
        }

        // VM-level state block (v4).
        let pic_master = read_len_prefixed(&mut r)?;
        let pic_slave = read_len_prefixed(&mut r)?;
        let ioapic = read_len_prefixed(&mut r)?;
        let pit2 = read_len_prefixed(&mut r)?;
        let clock = read_len_prefixed(&mut r)?;
        let vm_state = VmStateData {
            pic_master,
            pic_slave,
            ioapic,
            pit2,
            clock,
        };

        // Legacy-device state block (v6).
        let com1 = read_len_prefixed(&mut r)?;
        let com2 = read_len_prefixed(&mut r)?;
        let legacy_state = LegacyDeviceState { com1, com2 };

        // Virtio-net device state envelope (v7).
        let virtio_net_bytes = read_len_prefixed(&mut r)?;
        let virtio_net_state = virtio_net_state::decode(&virtio_net_bytes).map_err(|e| {
            SnapshotError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("virtio-net state decode: {e}"),
            ))
        })?;

        // Seek to the first region's payload (Golden) or first region's
        // dirty-bitmap section (Diff). For Diff in Phase 1 the body
        // after this offset is all zeros and is not yet consumed by
        // restore; Phase 2 will parse it.
        r.seek(SeekFrom::Start(region_offsets[0]))?;

        Ok(SnapshotReader {
            reader: r,
            path: path.to_path_buf(),
            format_version,
            kind,
            vcpu_count,
            mem_size_bytes,
            parent_sha256,
            vcpu_states,
            vm_state,
            legacy_state,
            virtio_net_state,
            regions,
            region_offsets,
            region_index: 0,
        })
    }

    /// Raw file descriptor of the underlying snapshot file. Borrowed; the
    /// `SnapshotReader` retains ownership for the lifetime of the returned
    /// fd. Intended for `mmap` calls that need to map the file directly.
    pub fn raw_fd(&self) -> RawFd {
        self.reader.get_ref().as_raw_fd()
    }

    /// Per-region `(guest_phys_addr, size, file_offset)` triples for the
    /// mmap fast path. Parallel to [`Self::regions`].
    pub fn regions_for_mmap(&self) -> Vec<RegionLocation> {
        self.regions
            .iter()
            .zip(self.region_offsets.iter())
            .map(|(r, off)| RegionLocation {
                guest_phys_addr: r.guest_phys_addr,
                size: r.size,
                file_offset: *off,
            })
            .collect()
    }

    /// Stream the next region's memory payload into `sink` (Phase-1
    /// memcpy restore path). Returns the descriptor of the region just
    /// streamed.
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
        // Seek to this region's page-aligned payload offset. (Open() left
        // us at region 0; second and later calls need an explicit seek.)
        let offset = self.region_offsets[self.region_index];
        self.reader.seek(SeekFrom::Start(offset))?;
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

    /// Verify the trailer is present at end of file.
    pub fn check_trailer(&mut self) -> Result<(), SnapshotError> {
        // Trailer is the last 4 bytes of the file regardless of how many
        // regions there were.
        let len = self.reader.get_ref().metadata()?.len();
        if len < 4 {
            return Err(SnapshotError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "snapshot too short for trailer",
            )));
        }
        self.reader.seek(SeekFrom::Start(len - 4))?;
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
