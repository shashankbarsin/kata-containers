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
pub mod vcpu_state;
pub mod vm_state;

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;

use self::metadata::{
    SnapshotMetadata, MAGIC, MAGIC_TRAILER, SNAPSHOT_FORMAT_VERSION, SNAPSHOT_PAGE_SIZE,
};
use self::vcpu_state::VcpuStateData;
use self::vm_state::VmStateData;

/// Configuration passed to [`VmmAction::SnapshotVm`](crate::api::v1::VmmAction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotConfig {
    /// Filesystem path where the snapshot blob should be written.
    pub snapshot_path: PathBuf,
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
/// File layout (all integers little-endian, v4 — I-008b extends v3):
///
/// ```text
/// [ 0.. 8] magic            : "ATEOMSN1"
/// [ 8..12] format_version   : u32   (currently 4)
/// [12..13] vcpu_count       : u8
/// [13..14] reserved         : u8    (== 0)
/// [14..16] reserved         : u16   (== 0)
/// [16..24] mem_size_bytes   : u64   (sum of all region sizes)
/// for each vCPU:
///     [1]                vcpu_id          : u8
///     [u32 len + bytes]  kvm_regs raw
///     [u32 len + bytes]  kvm_sregs raw
///     [u32 len + bytes]  kvm_msr_entry[] raw
///     [u32 len + bytes]  kvm_cpuid_entry2[] raw
///     [u32 len + bytes]  kvm_lapic_state raw       (v4)
///     [u32 len + bytes]  kvm_xsave raw             (v4)
///     [u32 len + bytes]  kvm_vcpu_events raw       (v4)
///     [u32 len + bytes]  kvm_mp_state raw          (v4)
/// [u32] memory_region_count
/// for each region:
///     [u64] guest_phys_addr
///     [u64] size
///     [u64] file_offset             (absolute, page-aligned)
/// VM-level state (v4):
///     [u32 len + bytes]  kvm_irqchip (PIC master)
///     [u32 len + bytes]  kvm_irqchip (PIC slave)
///     [u32 len + bytes]  kvm_irqchip (IOAPIC)
///     [u32 len + bytes]  kvm_pit_state2
///     [u32 len + bytes]  kvm_clock_data
/// <padding to next 4 KiB boundary>
/// for each region (in declaration order):
///     <size bytes at file_offset>
///     <padding to next 4 KiB boundary>
/// [4 bytes] trailer "END!"
/// ```
pub fn write_snapshot(
    cfg: &SnapshotConfig,
    vcpu_states: &[VcpuStateData],
    vm_state: &VmStateData,
    regions: &[MemoryRegionDescriptor],
    mut region_payload: impl FnMut(usize, &mut dyn Write) -> io::Result<()>,
) -> Result<SnapshotMetadata, SnapshotError> {
    let mem_size: u64 = regions.iter().map(|r| r.size).sum();
    let metadata = SnapshotMetadata {
        magic: MAGIC,
        format_version: SNAPSHOT_FORMAT_VERSION,
        vcpu_count: vcpu_states.len() as u8,
        mem_size_bytes: mem_size,
    };

    // Compute the on-disk size of the header (everything before payloads)
    // up-front so we can stamp absolute page-aligned `file_offset`s into the
    // region descriptor table without seeking back later.
    let header_len: u64 = {
        // Fixed prelude.
        let mut n: u64 = 8 + 4 + 1 + 1 + 2 + 8;
        // Per-vCPU records (8 len-prefixed blobs in v4).
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
        }
        // Region descriptor table: u32 count + (u64+u64+u64) per region.
        n += 4 + (regions.len() as u64) * 24;
        // VM-level state: 5 len-prefixed blobs.
        n += 4 + vm_state.pic_master.len() as u64;
        n += 4 + vm_state.pic_slave.len() as u64;
        n += 4 + vm_state.ioapic.len() as u64;
        n += 4 + vm_state.pit2.len() as u64;
        n += 4 + vm_state.clock.len() as u64;
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

    // Header.
    w.write_all(&metadata.magic)?;
    w.write_all(&metadata.format_version.to_le_bytes())?;
    w.write_all(&[metadata.vcpu_count])?;
    w.write_all(&[0u8])?; // reserved
    w.write_all(&0u16.to_le_bytes())?; // reserved
    w.write_all(&metadata.mem_size_bytes.to_le_bytes())?;

    // Per-vCPU state (8 len-prefixed blobs in v4).
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
