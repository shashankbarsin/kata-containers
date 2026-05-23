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
pub const SNAPSHOT_FORMAT_VERSION: u32 = 4;

/// Page size assumed by the v3 alignment scheme. Matches every architecture
/// we target (x86_64, aarch64) for `KVM_USER_MEMORY_REGION`.
pub const SNAPSHOT_PAGE_SIZE: u64 = 4096;

/// Decoded snapshot header / summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotMetadata {
    /// File magic — always [`MAGIC`].
    pub magic: [u8; 8],
    /// Snapshot format version.
    pub format_version: u32,
    /// Number of vCPUs whose state is recorded in the blob.
    pub vcpu_count: u8,
    /// Total guest memory size in bytes (sum of all region sizes).
    pub mem_size_bytes: u64,
}
