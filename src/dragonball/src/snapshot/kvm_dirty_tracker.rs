// Copyright (C) 2025 Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Thin wrapper over the `KVM_GET_DIRTY_LOG` ioctl.
//!
//! The kernel maintains a per-memslot dirty-page bitmap when the slot was
//! registered with `KVM_MEM_LOG_DIRTY_PAGES`. We use this for the diff
//! component of the golden+diff snapshot primitive — see planning-repo
//! ADR-0003.
//!
//! The wrapper is intentionally minimal: it does not interpret the bitmap, it
//! just hands back the raw `Vec<u64>` returned by `kvm-ioctls`. Bit `n` is set
//! if page `n` (4 KiB) of the slot has been written since the last reset of
//! the log.

use kvm_ioctls::VmFd;

/// Errors raised by the dirty-page tracker.
#[derive(Debug, thiserror::Error)]
pub enum DirtyTrackerError {
    /// The underlying `KVM_GET_DIRTY_LOG` ioctl failed. The most common
    /// failure mode is calling this against a memslot that was registered
    /// **without** `KVM_MEM_LOG_DIRTY_PAGES`, which surfaces as `EINVAL`.
    #[error("KVM_GET_DIRTY_LOG failed for slot {slot}: {source}")]
    Kvm {
        /// KVM memslot identifier the call was made against.
        slot: u32,
        /// Underlying kvm-ioctls error.
        #[source]
        source: kvm_ioctls::Error,
    },
}

/// Read and clear the dirty-page bitmap for `slot`.
///
/// `memory_size_bytes` must match the size that was passed to
/// `KVM_SET_USER_MEMORY_REGION` for this slot.
pub fn get_dirty_log(
    vm_fd: &VmFd,
    slot: u32,
    memory_size_bytes: usize,
) -> Result<Vec<u64>, DirtyTrackerError> {
    vm_fd
        .get_dirty_log(slot, memory_size_bytes)
        .map_err(|source| DirtyTrackerError::Kvm { slot, source })
}
