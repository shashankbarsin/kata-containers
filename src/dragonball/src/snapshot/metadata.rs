// Copyright (C) 2025 Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! On-disk snapshot metadata constants and layout descriptor.
//!
//! The format is owned by Dragonball — it is **not** Firecracker's
//! `versionize`/`Persist`, nor cloud-hypervisor's snapshot format. See
//! planning-repo ADR-0003 for rationale.

/// Magic bytes prefixing every snapshot blob ("ATEOMSN1").
pub const MAGIC: [u8; 8] = *b"ATEOMSN1";

/// Trailer bytes terminating every snapshot blob ("END!").
pub const MAGIC_TRAILER: [u8; 4] = *b"END!";

/// Current snapshot format version. Bump on any layout change; never reuse
/// values. Each version must be readable by all subsequent versions.
/// Bumped to 2 in I-007 when per-region memory payload was added after the
/// region descriptor table; restore reads payload bytes for each region.
/// Bumped to 3 in I-008a: region descriptors carry an absolute, page-aligned
/// `file_offset` and the descriptor table is padded to a 4 KiB boundary so
/// that each region payload starts on a page boundary — enabling
/// `mmap(MAP_PRIVATE)` of the snapshot file directly as guest memory.
/// Bumped to 4 in I-008b: per-vCPU records gain `lapic` / `xsave` /
/// `vcpu_events` / `mp_state` blobs and a new VM-level state block
/// (PIC master/slave, IOAPIC, PIT2, KVM_CLOCK) is written between the
/// region descriptor table and the header padding. This is the minimum
/// state needed for a no-boot mmap restore.
/// Bumped to 5 in I-008c-3b: per-vCPU records gain an `xcrs` blob so XCR0
/// (AVX-enable bit) survives restore — fixes post-restore #UD on AVX insns.
/// Bumped to 6 in I-008c-3c: legacy-device state block (COM1 / COM2
/// 8250-UART register + FIFO) written after the VM-level state block, so
/// the post-restore UART honours IER and asserts COM1 IRQ on host→guest
/// `raw_input`.
/// Bumped to 7 (I-003 Phase 1): virtio-net device state envelope written
/// after the legacy-device state block. Phase 1 captures per-device
/// interface spec (iface_id, host TAP name, MAC, queue geometry); Phase
/// 2 will extend the per-device payload with live queue cursors + ring
/// GPAs + negotiated features.
/// Bumped to 8 (I-003 Phase 2): per-device record gains `acked_features`
/// and a per-queue array carrying ring GPAs (`desc_table`, `avail_ring`,
/// `used_ring`), `ready`, `event_idx_enabled`, `next_avail`, `next_used`,
/// and `size`. This is the minimum state needed for a synthesized
/// post-restore device activation (re-binding the TAP to the virtio-net
/// queues without the guest re-issuing the MMIO config writes).
/// Bumped to 9 (I-004 Phase 1): header gains a `snapshot_kind` byte
/// (0 = Golden, 1 = Diff) in the previously-reserved slot at offset 13,
/// and a fixed-width `parent_sha256: [u8; 32]` immediately after
/// `mem_size_bytes`. For Golden snapshots the `parent_sha256` field is
/// all-zero. For Diff snapshots it holds the SHA-256 of the parent
/// golden file the diff is built against, so restore can verify the
/// right base is being applied. Diffs additionally carry per-region
/// dirty bitmaps in place of embedded region payloads — see
/// [`crate::snapshot`] for the full layout.
pub const SNAPSHOT_FORMAT_VERSION: u32 = 9;

/// Page size assumed by the v3 alignment scheme. Matches every architecture
/// we target (x86_64, aarch64) for `KVM_USER_MEMORY_REGION`.
pub const SNAPSHOT_PAGE_SIZE: u64 = 4096;

/// Snapshot kind discriminator written into the v9 header.
///
/// See planning-repo ADR-0003 and audit I-004 for the golden + diff design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SnapshotKind {
    /// Full snapshot: self-contained, restorable on its own.
    Golden = 0,
    /// Incremental diff against a parent golden. Restore requires the
    /// parent golden file (referenced by `parent_sha256` in the header).
    Diff = 1,
}

impl SnapshotKind {
    /// Wire byte for the kind discriminator.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse a wire byte, returning `None` for unknown values.
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(SnapshotKind::Golden),
            1 => Some(SnapshotKind::Diff),
            _ => None,
        }
    }
}

/// Decoded snapshot header / summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotMetadata {
    /// File magic — always [`MAGIC`].
    pub magic: [u8; 8],
    /// Snapshot format version.
    pub format_version: u32,
    /// Snapshot kind (Golden or Diff). Carried in the v9 header at
    /// offset 13.
    pub kind: SnapshotKind,
    /// Number of vCPUs whose state is recorded in the blob.
    pub vcpu_count: u8,
    /// Total guest memory size in bytes (sum of all region sizes).
    pub mem_size_bytes: u64,
    /// SHA-256 of the parent golden snapshot file. All zero for Golden
    /// snapshots. For Diff snapshots, set to the hash of the file the
    /// diff is built against; restore uses this to verify the right
    /// base is being applied (audit I-004 §4 Q2).
    pub parent_sha256: [u8; 32],
}
