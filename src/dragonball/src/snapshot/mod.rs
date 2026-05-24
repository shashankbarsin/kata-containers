// Copyright (C) 2025 Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Golden + diff snapshot/restore primitive for Dragonball microVMs.
//!
//! This module is being grown from scratch as part of the Azure Agent Substrate
//! POC (see planning-repo ADR-0003). Phase 1 (I-006) lands a minimal stub:
//!
//! * a custom on-disk format with explicit magic + version (NOT Firecracker's
//!   `versionize` / `Persist`),
//! * vCPU register capture (x86_64 only for the POC),
//! * memory-region descriptors (no page contents yet — that arrives in I-007),
//! * a `KVM_GET_DIRTY_LOG` wrapper that proves the `KVM_MEM_LOG_DIRTY_PAGES`
//!   flag is being plumbed through `set_user_memory_region`.
//!
//! Device state, virtio queues, and incremental (diff) snapshots all land in
//! Phase 2. The format below is intentionally simple but versioned so that we
//! can evolve it without ambiguity.

pub mod kvm_dirty_tracker;
pub mod metadata;
pub mod reader;
pub mod serial_state;
pub mod vcpu_state;
pub mod virtio_net_state;
pub mod vm_state;

use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use self::metadata::{
    SnapshotKind, SnapshotMetadata, MAGIC, MAGIC_TRAILER, SNAPSHOT_FORMAT_VERSION,
    SNAPSHOT_PAGE_SIZE,
};
use self::serial_state::LegacyDeviceState;
use self::vcpu_state::VcpuStateData;
use self::virtio_net_state::VirtioNetState;
use self::vm_state::VmStateData;

/// Configuration passed to [`VmmAction::SnapshotVm`](crate::api::v1::VmmAction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotConfig {
    /// Filesystem path where the snapshot blob should be written.
    pub snapshot_path: PathBuf,
    /// Snapshot kind. `Golden` produces a self-contained snapshot.
    /// `Diff` produces an incremental snapshot against
    /// `parent_golden_path`; the parent file is hashed at write time
    /// and the SHA-256 stamped into the v9 header (audit I-004 §4 Q2).
    pub kind: SnapshotKind,
    /// Required when `kind == SnapshotKind::Diff`; ignored otherwise.
    /// Path to the parent golden snapshot file this diff is built
    /// against. Hashed at write time to populate `parent_sha256`.
    pub parent_golden_path: Option<PathBuf>,
}

impl SnapshotConfig {
    /// Construct a Golden snapshot config — the common case.
    pub fn golden(snapshot_path: PathBuf) -> Self {
        Self {
            snapshot_path,
            kind: SnapshotKind::Golden,
            parent_golden_path: None,
        }
    }

    /// Construct a Diff snapshot config against the given parent
    /// golden file.
    pub fn diff(snapshot_path: PathBuf, parent_golden_path: PathBuf) -> Self {
        Self {
            snapshot_path,
            kind: SnapshotKind::Diff,
            parent_golden_path: Some(parent_golden_path),
        }
    }
}

/// Configuration passed to [`VmmAction::RestoreVm`](crate::api::v1::VmmAction).
///
/// Phase 1 (I-007): the snapshot file produced by an earlier
/// `SnapshotVm` is overlaid on top of an already-booted, already-paused
/// microVM. The substrate-side trait orchestrates boot+pause+restore as a
/// single `Vmm::restore` call; this struct only carries the path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreConfig {
    /// Filesystem path of the snapshot blob to load.
    pub snapshot_path: PathBuf,
}

/// Errors returned by the snapshot subsystem.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// Filesystem / I/O failure while writing the snapshot blob.
    #[error("snapshot I/O error: {0}")]
    Io(#[from] io::Error),

    /// The VM is not in a state from which a snapshot can be taken
    /// (must be Paused).
    #[error("snapshot can only be taken from a paused VM (current state: {0})")]
    NotPaused(String),

    /// vCPU state capture failed.
    #[error("vCPU state capture failed: {0}")]
    VcpuCapture(String),
}

/// Lightweight descriptor of a guest memory region recorded in the snapshot.
///
/// Phase 1 captures only the addressing metadata, not the page contents.
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegionDescriptor {
    /// Guest physical address of the start of the region.
    pub guest_phys_addr: u64,
    /// Size of the region in bytes.
    pub size: u64,
}

/// Write a snapshot blob to `cfg.snapshot_path`.
///
/// Dispatches on `cfg.kind`:
/// * [`SnapshotKind::Golden`] — self-contained snapshot with full
///   region payloads; restorable on its own. See
///   [`write_golden_snapshot`].
/// * [`SnapshotKind::Diff`] — incremental snapshot recording only the
///   pages dirtied since the parent golden, prefixed with a SHA-256
///   reference to the parent. See [`write_diff_snapshot_phase1`].
///   Phase 1 emits an empty dirty set (Phase 2 wires the bits up).
///
/// `region_payload` is invoked once per region for Golden snapshots and
/// is ignored for Diff snapshots.
///
/// File layout (all integers little-endian, v9 — adds snapshot-kind
/// byte at offset 13 and a fixed-width `parent_sha256` at offset 24,
/// per audit I-004 Phase 1):
///
/// ```text
/// [ 0.. 8] magic            : "ATEOMSN1"
/// [ 8..12] format_version   : u32   (currently 9)
/// [12..13] vcpu_count       : u8
/// [13..14] snapshot_kind    : u8    (0 = Golden, 1 = Diff)
/// [14..16] reserved         : u16   (== 0)
/// [16..24] mem_size_bytes   : u64   (sum of all region sizes)
/// [24..56] parent_sha256    : [u8; 32]
///                                   (Golden: all zero;
///                                    Diff:   SHA-256 of parent file)
/// for each vCPU:
///     [1]                vcpu_id          : u8
///     [u32 len + bytes]  kvm_regs raw
///     [u32 len + bytes]  kvm_sregs raw
///     [u32 len + bytes]  kvm_msr_entry[] raw
///     [u32 len + bytes]  kvm_cpuid_entry2[] raw
///     [u32 len + bytes]  kvm_lapic_state raw
///     [u32 len + bytes]  kvm_xsave raw
///     [u32 len + bytes]  kvm_vcpu_events raw
///     [u32 len + bytes]  kvm_mp_state raw
///     [u32 len + bytes]  kvm_xcrs raw
/// [u32] memory_region_count
/// for each region:
///     [u64] guest_phys_addr
///     [u64] size
///     [u64] file_offset             (absolute, page-aligned)
///                                   Golden: offset of full region payload
///                                   Diff:   offset of per-region dirty bitmap
/// VM-level state (5 len-prefixed blobs)
/// Legacy-device state (2 len-prefixed blobs)
/// Virtio-net device state (1 len-prefixed blob)
/// <padding to next 4 KiB boundary>
/// for each region (in declaration order):
///     Golden: <size bytes>                       at file_offset
///     Diff:   <bitmap_bytes>                     at file_offset
///             (bitmap_bytes = ceil(size/4096/64)*8;
///              Phase 1: all-zero. Phase 2 will append concatenated
///              dirty-page payloads after the bitmap in scan order.)
///     <padding to next 4 KiB boundary>
/// [4 bytes] trailer "END!"
/// ```
pub fn write_snapshot(
    cfg: &SnapshotConfig,
    vcpu_states: &[VcpuStateData],
    vm_state: &VmStateData,
    legacy_state: &LegacyDeviceState,
    virtio_net_state: &VirtioNetState,
    regions: &[MemoryRegionDescriptor],
    region_payload: impl FnMut(usize, &mut dyn Write) -> io::Result<()>,
) -> Result<SnapshotMetadata, SnapshotError> {
    match cfg.kind {
        SnapshotKind::Golden => write_golden_snapshot(
            cfg,
            vcpu_states,
            vm_state,
            legacy_state,
            virtio_net_state,
            regions,
            region_payload,
        ),
        SnapshotKind::Diff => write_diff_snapshot_phase1(
            cfg,
            vcpu_states,
            vm_state,
            legacy_state,
            virtio_net_state,
            regions,
        ),
    }
}

/// Compute the SHA-256 of the file at `path`. Used to stamp
/// `parent_sha256` into a Diff snapshot header so restore can verify
/// the right base is being applied (audit I-004 §4 Q2).
pub fn hash_file_sha256(path: &std::path::Path) -> io::Result<[u8; 32]> {
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20]; // 1 MiB chunks.
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Bytes-per-region of the dirty bitmap section (one bit per 4 KiB page,
/// packed into LE u64 words). Matches the shape returned by
/// `KVM_GET_DIRTY_LOG`.
fn dirty_bitmap_bytes_for_region(region_size: u64) -> u64 {
    let num_pages = region_size.div_ceil(SNAPSHOT_PAGE_SIZE);
    let num_words = num_pages.div_ceil(64);
    num_words * 8
}

/// Write a Golden snapshot. Self-contained: header → vCPU state →
/// region descriptors with payload offsets → VM/legacy/virtio-net
/// state → full region payloads → trailer. See [`write_snapshot`] for
/// the full layout.
fn write_golden_snapshot(
    cfg: &SnapshotConfig,
    vcpu_states: &[VcpuStateData],
    vm_state: &VmStateData,
    legacy_state: &LegacyDeviceState,
    virtio_net_state: &VirtioNetState,
    regions: &[MemoryRegionDescriptor],
    mut region_payload: impl FnMut(usize, &mut dyn Write) -> io::Result<()>,
) -> Result<SnapshotMetadata, SnapshotError> {
    let mem_size: u64 = regions.iter().map(|r| r.size).sum();
    let metadata = SnapshotMetadata {
        magic: MAGIC,
        format_version: SNAPSHOT_FORMAT_VERSION,
        kind: SnapshotKind::Golden,
        vcpu_count: vcpu_states.len() as u8,
        mem_size_bytes: mem_size,
        parent_sha256: [0u8; 32],
    };

    // Encode the v7 virtio-net envelope once and reuse the bytes for both
    // header sizing and the write.
    let virtio_net_bytes = virtio_net_state::encode(virtio_net_state);

    // Compute the on-disk size of the header (everything before payloads)
    // up-front so we can stamp absolute page-aligned `file_offset`s into the
    // region descriptor table without seeking back later.
    let header_len: u64 = {
        // Fixed prelude (v9: 56 bytes — 24 of original + 32 parent_sha256).
        let mut n: u64 = 8 + 4 + 1 + 1 + 2 + 8 + 32;
        // Per-vCPU records (9 len-prefixed blobs in v5).
        for st in vcpu_states {
            n += 1; // vcpu_id
            n += 4 + st.regs.len() as u64;
            n += 4 + st.sregs.len() as u64;
            n += 4 + st.msrs.len() as u64;
            n += 4 + st.cpuid_entries.len() as u64;
            n += 4 + st.lapic.len() as u64;
            n += 4 + st.xsave.len() as u64;
            n += 4 + st.vcpu_events.len() as u64;
            n += 4 + st.mp_state.len() as u64;
            n += 4 + st.xcrs.len() as u64;
        }
        // Region descriptor table: u32 count + (u64+u64+u64) per region.
        n += 4 + (regions.len() as u64) * 24;
        // VM-level state: 5 len-prefixed blobs.
        n += 4 + vm_state.pic_master.len() as u64;
        n += 4 + vm_state.pic_slave.len() as u64;
        n += 4 + vm_state.ioapic.len() as u64;
        n += 4 + vm_state.pit2.len() as u64;
        n += 4 + vm_state.clock.len() as u64;
        // Legacy-device state: 2 len-prefixed blobs (v6).
        n += 4 + legacy_state.com1.len() as u64;
        n += 4 + legacy_state.com2.len() as u64;
        // Virtio-net device state envelope (v7): single len-prefixed blob.
        let virtio_net_bytes_len = virtio_net_bytes.len() as u64;
        n += 4 + virtio_net_bytes_len;
        n
    };
    let payloads_start = align_up(header_len, SNAPSHOT_PAGE_SIZE);
    let header_pad = (payloads_start - header_len) as usize;

    // Pre-compute each region's absolute file_offset; pad each payload tail
    // to a 4 KiB boundary so subsequent regions also land aligned.
    let mut region_offsets: Vec<u64> = Vec::with_capacity(regions.len());
    let mut cursor = payloads_start;
    for r in regions {
        region_offsets.push(cursor);
        cursor = align_up(cursor + r.size, SNAPSHOT_PAGE_SIZE);
    }

    let file = File::create(&cfg.snapshot_path)?;
    let mut w = BufWriter::new(file);

    // Header (v9).
    write_v9_common_header(
        &mut w,
        SnapshotKind::Golden,
        vcpu_states.len() as u8,
        mem_size,
        &[0u8; 32],
    )?;

    // Per-vCPU state (9 len-prefixed blobs in v5).
    for state in vcpu_states {
        w.write_all(&[state.vcpu_id])?;
        write_len_prefixed(&mut w, &state.regs)?;
        write_len_prefixed(&mut w, &state.sregs)?;
        write_len_prefixed(&mut w, &state.msrs)?;
        write_len_prefixed(&mut w, &state.cpuid_entries)?;
        write_len_prefixed(&mut w, &state.lapic)?;
        write_len_prefixed(&mut w, &state.xsave)?;
        write_len_prefixed(&mut w, &state.vcpu_events)?;
        write_len_prefixed(&mut w, &state.mp_state)?;
        write_len_prefixed(&mut w, &state.xcrs)?;
    }

    // Memory region descriptor table.
    w.write_all(&(regions.len() as u32).to_le_bytes())?;
    for (r, off) in regions.iter().zip(region_offsets.iter()) {
        w.write_all(&r.guest_phys_addr.to_le_bytes())?;
        w.write_all(&r.size.to_le_bytes())?;
        w.write_all(&off.to_le_bytes())?;
    }

    // VM-level state block (v4).
    write_len_prefixed(&mut w, &vm_state.pic_master)?;
    write_len_prefixed(&mut w, &vm_state.pic_slave)?;
    write_len_prefixed(&mut w, &vm_state.ioapic)?;
    write_len_prefixed(&mut w, &vm_state.pit2)?;
    write_len_prefixed(&mut w, &vm_state.clock)?;

    // Legacy-device state block (v6).
    write_len_prefixed(&mut w, &legacy_state.com1)?;
    write_len_prefixed(&mut w, &legacy_state.com2)?;

    // Virtio-net device state envelope (v7). Encoded once above for header
    // sizing; reuse the bytes here.
    write_len_prefixed(&mut w, &virtio_net_bytes)?;
    // Pad header out to the first payload's 4 KiB boundary.
    write_zero_pad(&mut w, header_pad)?;

    // Region payloads, each padded out to the next 4 KiB boundary so the
    // following payload (and the trailer in the single-region case) starts
    // on an aligned offset.
    for (idx, r) in regions.iter().enumerate() {
        region_payload(idx, &mut w)?;
        let pad = (align_up(r.size, SNAPSHOT_PAGE_SIZE) - r.size) as usize;
        write_zero_pad(&mut w, pad)?;
    }

    // Trailer.
    w.write_all(&MAGIC_TRAILER)?;
    w.flush()?;
    Ok(metadata)
}

/// Write a Diff snapshot — Phase 1 of audit I-004.
///
/// Phase 1 emits a well-formed Diff blob with an **empty** dirty set:
/// the per-region bitmap is zero-filled and there are no dirty-page
/// payloads. The parent golden file is hashed at write time and the
/// SHA-256 stamped into the header so restore (Phase 2) can verify it
/// has the right base.
///
/// vCPU / VM-level / legacy / virtio-net state are captured in full,
/// same as Golden (audit I-004 §4 Q10).
fn write_diff_snapshot_phase1(
    cfg: &SnapshotConfig,
    vcpu_states: &[VcpuStateData],
    vm_state: &VmStateData,
    legacy_state: &LegacyDeviceState,
    virtio_net_state: &VirtioNetState,
    regions: &[MemoryRegionDescriptor],
) -> Result<SnapshotMetadata, SnapshotError> {
    let parent_path = cfg.parent_golden_path.as_ref().ok_or_else(|| {
        SnapshotError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Diff snapshot requires SnapshotConfig::parent_golden_path",
        ))
    })?;
    let parent_sha256 = hash_file_sha256(parent_path)?;

    let mem_size: u64 = regions.iter().map(|r| r.size).sum();
    let metadata = SnapshotMetadata {
        magic: MAGIC,
        format_version: SNAPSHOT_FORMAT_VERSION,
        kind: SnapshotKind::Diff,
        vcpu_count: vcpu_states.len() as u8,
        mem_size_bytes: mem_size,
        parent_sha256,
    };

    let virtio_net_bytes = virtio_net_state::encode(virtio_net_state);

    // Header length up-front so we can stamp file_offsets for each
    // region's dirty-bitmap section.
    let header_len: u64 = {
        let mut n: u64 = 8 + 4 + 1 + 1 + 2 + 8 + 32;
        for st in vcpu_states {
            n += 1;
            n += 4 + st.regs.len() as u64;
            n += 4 + st.sregs.len() as u64;
            n += 4 + st.msrs.len() as u64;
            n += 4 + st.cpuid_entries.len() as u64;
            n += 4 + st.lapic.len() as u64;
            n += 4 + st.xsave.len() as u64;
            n += 4 + st.vcpu_events.len() as u64;
            n += 4 + st.mp_state.len() as u64;
            n += 4 + st.xcrs.len() as u64;
        }
        n += 4 + (regions.len() as u64) * 24;
        n += 4 + vm_state.pic_master.len() as u64;
        n += 4 + vm_state.pic_slave.len() as u64;
        n += 4 + vm_state.ioapic.len() as u64;
        n += 4 + vm_state.pit2.len() as u64;
        n += 4 + vm_state.clock.len() as u64;
        n += 4 + legacy_state.com1.len() as u64;
        n += 4 + legacy_state.com2.len() as u64;
        n += 4 + virtio_net_bytes.len() as u64;
        n
    };
    let payloads_start = align_up(header_len, SNAPSHOT_PAGE_SIZE);
    let header_pad = (payloads_start - header_len) as usize;

    // Each region's `file_offset` points to its dirty-bitmap section.
    // Bitmap is page-aligned (so a Phase 2 mmap-overlay could in
    // principle access it directly). Phase 1 has no payload after the
    // bitmap; the next region's bitmap (or the trailer) follows.
    let mut region_offsets: Vec<u64> = Vec::with_capacity(regions.len());
    let mut cursor = payloads_start;
    for r in regions {
        region_offsets.push(cursor);
        let bitmap_bytes = dirty_bitmap_bytes_for_region(r.size);
        cursor = align_up(cursor + bitmap_bytes, SNAPSHOT_PAGE_SIZE);
    }

    let file = File::create(&cfg.snapshot_path)?;
    let mut w = BufWriter::new(file);

    write_v9_common_header(
        &mut w,
        SnapshotKind::Diff,
        vcpu_states.len() as u8,
        mem_size,
        &parent_sha256,
    )?;

    for state in vcpu_states {
        w.write_all(&[state.vcpu_id])?;
        write_len_prefixed(&mut w, &state.regs)?;
        write_len_prefixed(&mut w, &state.sregs)?;
        write_len_prefixed(&mut w, &state.msrs)?;
        write_len_prefixed(&mut w, &state.cpuid_entries)?;
        write_len_prefixed(&mut w, &state.lapic)?;
        write_len_prefixed(&mut w, &state.xsave)?;
        write_len_prefixed(&mut w, &state.vcpu_events)?;
        write_len_prefixed(&mut w, &state.mp_state)?;
        write_len_prefixed(&mut w, &state.xcrs)?;
    }

    w.write_all(&(regions.len() as u32).to_le_bytes())?;
    for (r, off) in regions.iter().zip(region_offsets.iter()) {
        w.write_all(&r.guest_phys_addr.to_le_bytes())?;
        w.write_all(&r.size.to_le_bytes())?;
        w.write_all(&off.to_le_bytes())?;
    }

    write_len_prefixed(&mut w, &vm_state.pic_master)?;
    write_len_prefixed(&mut w, &vm_state.pic_slave)?;
    write_len_prefixed(&mut w, &vm_state.ioapic)?;
    write_len_prefixed(&mut w, &vm_state.pit2)?;
    write_len_prefixed(&mut w, &vm_state.clock)?;

    write_len_prefixed(&mut w, &legacy_state.com1)?;
    write_len_prefixed(&mut w, &legacy_state.com2)?;

    write_len_prefixed(&mut w, &virtio_net_bytes)?;
    write_zero_pad(&mut w, header_pad)?;

    // Per-region dirty bitmaps. Phase 1: all zero. Phase 2 will write
    // the bits from `KVM_GET_DIRTY_LOG` and append the concatenated
    // dirty-page payloads after each bitmap.
    for r in regions {
        let bitmap_bytes = dirty_bitmap_bytes_for_region(r.size) as usize;
        write_zero_pad(&mut w, bitmap_bytes)?;
        let pad = (align_up(bitmap_bytes as u64, SNAPSHOT_PAGE_SIZE) - bitmap_bytes as u64) as usize;
        write_zero_pad(&mut w, pad)?;
    }

    w.write_all(&MAGIC_TRAILER)?;
    w.flush()?;
    Ok(metadata)
}

/// Write the v9 common header (offsets 0..56). Used by both Golden and
/// Diff writers.
fn write_v9_common_header<W: Write>(
    w: &mut W,
    kind: SnapshotKind,
    vcpu_count: u8,
    mem_size_bytes: u64,
    parent_sha256: &[u8; 32],
) -> io::Result<()> {
    w.write_all(&MAGIC)?;
    w.write_all(&SNAPSHOT_FORMAT_VERSION.to_le_bytes())?;
    w.write_all(&[vcpu_count])?;
    w.write_all(&[kind.as_u8()])?;
    w.write_all(&0u16.to_le_bytes())?; // reserved
    w.write_all(&mem_size_bytes.to_le_bytes())?;
    w.write_all(parent_sha256)?;
    Ok(())
}

#[inline]
fn align_up(value: u64, alignment: u64) -> u64 {
    debug_assert!(alignment.is_power_of_two());
    (value + alignment - 1) & !(alignment - 1)
}

fn write_zero_pad<W: Write>(w: &mut W, n: usize) -> io::Result<()> {
    if n == 0 {
        return Ok(());
    }
    const Z: [u8; 4096] = [0u8; 4096];
    let mut remaining = n;
    while remaining > 0 {
        let take = remaining.min(Z.len());
        w.write_all(&Z[..take])?;
        remaining -= take;
    }
    Ok(())
}

fn write_len_prefixed<W: Write>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    w.write_all(&(bytes.len() as u32).to_le_bytes())?;
    w.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::reader::SnapshotReader;
    use crate::snapshot::vcpu_state::VcpuStateData;
    use crate::snapshot::vm_state::VmStateData;
    use crate::snapshot::virtio_net_state::VirtioNetState;
    use crate::snapshot::serial_state::LegacyDeviceState;
    use std::env::temp_dir;
    use std::fs;

    /// Audit I-004 Phase 1 exit criterion: writing a Diff snapshot
    /// against a freshly-paused VM produces a well-formed file whose
    /// header carries the parent's SHA-256, and the reader round-trips
    /// the `kind` and `parent_sha256` fields.
    #[test]
    fn diff_snapshot_round_trips_parent_sha256() {
        let dir = temp_dir().join(format!("ateom-i004-phase1-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let golden_path = dir.join("golden.snap");
        let diff_path = dir.join("diff.snap");

        let vcpus = vec![VcpuStateData::default()];
        let vm_state = VmStateData::default();
        let legacy_state = LegacyDeviceState::default();
        let virtio_net_state = VirtioNetState::default();
        let regions = vec![MemoryRegionDescriptor {
            guest_phys_addr: 0,
            size: 4096,
        }];

        // Write a Golden snapshot with a single 4 KiB region of zeros.
        let golden_cfg = SnapshotConfig::golden(golden_path.clone());
        let golden_meta = write_snapshot(
            &golden_cfg,
            &vcpus,
            &vm_state,
            &legacy_state,
            &virtio_net_state,
            &regions,
            |_idx, w| {
                w.write_all(&[0u8; 4096])?;
                Ok(())
            },
        )
        .expect("golden write");
        assert_eq!(golden_meta.kind, SnapshotKind::Golden);
        assert_eq!(golden_meta.parent_sha256, [0u8; 32]);
        let expected_parent_hash = hash_file_sha256(&golden_path).unwrap();

        // Write a Diff snapshot against the golden file.
        let diff_cfg = SnapshotConfig::diff(diff_path.clone(), golden_path.clone());
        let diff_meta = write_snapshot(
            &diff_cfg,
            &vcpus,
            &vm_state,
            &legacy_state,
            &virtio_net_state,
            &regions,
            |_idx, _w| Ok(()), // ignored for Diff
        )
        .expect("diff write");
        assert_eq!(diff_meta.kind, SnapshotKind::Diff);
        assert_eq!(diff_meta.parent_sha256, expected_parent_hash);

        // Round-trip read.
        let golden_reader = SnapshotReader::open(&golden_path).expect("open golden");
        assert_eq!(golden_reader.kind, SnapshotKind::Golden);
        assert_eq!(golden_reader.parent_sha256, [0u8; 32]);
        assert_eq!(golden_reader.format_version, SNAPSHOT_FORMAT_VERSION);

        let diff_reader = SnapshotReader::open(&diff_path).expect("open diff");
        assert_eq!(diff_reader.kind, SnapshotKind::Diff);
        assert_eq!(diff_reader.parent_sha256, expected_parent_hash);
        assert_eq!(diff_reader.format_version, SNAPSHOT_FORMAT_VERSION);

        let _ = fs::remove_dir_all(&dir);
    }
}
