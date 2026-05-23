// Copyright (C) 2025 Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-vCPU register snapshot data.
//!
//! Phase 1 captures the bare minimum needed to round-trip a paused x86_64
//! vCPU through KVM: general-purpose regs, special regs, the model-specific
//! register set Dragonball already enumerates as "supported", and the active
//! CPUID layout.
//!
//! On-disk representation is raw bytes of the `kvm_*` C structs. This is fine
//! while sender and receiver are the same Dragonball build; once we cross
//! version boundaries the encoded form will move into a versioned bincode
//! payload (planning-repo ADR-0003).

#[cfg(target_arch = "x86_64")]
use kvm_bindings::{kvm_cpuid_entry2, kvm_msr_entry, kvm_regs, kvm_sregs, CpuId, Msrs};
#[cfg(target_arch = "x86_64")]
use kvm_ioctls::VcpuFd;

/// Raw register state captured from a paused vCPU.
///
/// The four register-set fields are wire-format raw bytes — the kernel
/// `kvm_*` C structs are `#[repr(C)]` so a direct `as_bytes`/`from_bytes`
/// round-trip on the same machine is safe.
#[derive(Debug, Default, Clone)]
pub struct VcpuStateData {
    /// Logical vCPU id (0-indexed).
    pub vcpu_id: u8,
    /// Raw `kvm_regs` bytes.
    pub regs: Vec<u8>,
    /// Raw `kvm_sregs` bytes.
    pub sregs: Vec<u8>,
    /// Concatenated raw `kvm_msr_entry` bytes (one entry per supported MSR).
    pub msrs: Vec<u8>,
    /// Concatenated raw `kvm_cpuid_entry2` bytes.
    pub cpuid_entries: Vec<u8>,
}

/// Errors raised while capturing per-vCPU state.
#[derive(Debug, thiserror::Error)]
pub enum VcpuStateError {
    /// A KVM ioctl failed during capture.
    #[error("kvm ioctl failed during vcpu-state capture: {0}")]
    Kvm(#[from] kvm_ioctls::Error),

    /// Failed to build the MSR descriptor block expected by KVM.
    #[error("failed to build Msrs FAM struct: {0}")]
    BuildMsrs(String),
}

#[cfg(target_arch = "x86_64")]
/// Capture the full Phase-1 register snapshot for `fd`.
///
/// `msr_indices` is the list of MSR indices that the kernel reported as
/// supported (see `KvmContext::supported_msrs`). The vCPU thread re-builds
/// the FAM-style `Msrs` block locally because that struct is not `Send`.
pub fn capture(
    vcpu_id: u8,
    fd: &VcpuFd,
    cpuid_entries: &[kvm_cpuid_entry2],
    msr_indices: &[u32],
) -> Result<VcpuStateData, VcpuStateError> {
    let regs: kvm_regs = fd.get_regs()?;
    let sregs: kvm_sregs = fd.get_sregs()?;

    // Build a mutable Msrs from the supported indices and let KVM fill in .data.
    let entries: Vec<kvm_msr_entry> = msr_indices
        .iter()
        .map(|index| kvm_msr_entry {
            index: *index,
            reserved: 0,
            data: 0,
        })
        .collect();
    let mut msrs = Msrs::from_entries(&entries)
        .map_err(|e| VcpuStateError::BuildMsrs(format!("{e:?}")))?;
    let read = fd.get_msrs(&mut msrs)?;
    let msr_entries = &msrs.as_slice()[..read];

    Ok(VcpuStateData {
        vcpu_id,
        regs: struct_to_bytes(&regs),
        sregs: struct_to_bytes(&sregs),
        msrs: slice_to_bytes(msr_entries),
        cpuid_entries: slice_to_bytes(cpuid_entries),
    })
}

#[cfg(not(target_arch = "x86_64"))]
#[allow(unused_variables)]
/// Placeholder for non-x86_64. aarch64 capture lands in a later phase.
pub fn capture(
    vcpu_id: u8,
    _fd: &(),
    _cpuid_entries: &[()],
    _msr_indices: &[u32],
) -> Result<VcpuStateData, VcpuStateError> {
    Ok(VcpuStateData {
        vcpu_id,
        ..Default::default()
    })
}

#[cfg(target_arch = "x86_64")]
fn struct_to_bytes<T: Copy>(value: &T) -> Vec<u8> {
    // Safe: T is a #[repr(C)] POD KVM struct, and we only read it.
    let slice = unsafe {
        std::slice::from_raw_parts(
            value as *const T as *const u8,
            std::mem::size_of::<T>(),
        )
    };
    slice.to_vec()
}

#[cfg(target_arch = "x86_64")]
fn slice_to_bytes<T: Copy>(items: &[T]) -> Vec<u8> {
    let byte_len = std::mem::size_of_val(items);
    let slice =
        unsafe { std::slice::from_raw_parts(items.as_ptr() as *const u8, byte_len) };
    slice.to_vec()
}

#[cfg(target_arch = "x86_64")]
/// Apply a previously captured `VcpuStateData` to a paused vCPU.
///
/// Inverse of [`capture`]. Calls `KVM_SET_REGS`, `KVM_SET_SREGS`,
/// `KVM_SET_MSRS`, `KVM_SET_CPUID2`. Used by the I-007 restore path
/// (planning-repo ADR-0003).
pub fn apply(fd: &VcpuFd, state: &VcpuStateData) -> Result<(), VcpuStateError> {
    use std::mem::size_of;

    // 1. CPUID — must come before SET_SREGS per KVM API conventions.
    if !state.cpuid_entries.is_empty() {
        let entry_size = size_of::<kvm_cpuid_entry2>();
        if state.cpuid_entries.len() % entry_size != 0 {
            return Err(VcpuStateError::BuildMsrs(format!(
                "cpuid blob length {} not a multiple of entry size {entry_size}",
                state.cpuid_entries.len()
            )));
        }
        let count = state.cpuid_entries.len() / entry_size;
        let entries: &[kvm_cpuid_entry2] = unsafe {
            std::slice::from_raw_parts(
                state.cpuid_entries.as_ptr() as *const kvm_cpuid_entry2,
                count,
            )
        };
        let cpuid =
            CpuId::from_entries(entries).map_err(|e| VcpuStateError::BuildMsrs(format!("{e:?}")))?;
        fd.set_cpuid2(&cpuid)?;
    }

    // 2. SREGS, then REGS.
    if state.sregs.len() != size_of::<kvm_sregs>() {
        return Err(VcpuStateError::BuildMsrs(format!(
            "sregs blob length {} != sizeof(kvm_sregs) {}",
            state.sregs.len(),
            size_of::<kvm_sregs>()
        )));
    }
    let sregs: kvm_sregs = unsafe { std::ptr::read(state.sregs.as_ptr() as *const kvm_sregs) };
    fd.set_sregs(&sregs)?;

    if state.regs.len() != size_of::<kvm_regs>() {
        return Err(VcpuStateError::BuildMsrs(format!(
            "regs blob length {} != sizeof(kvm_regs) {}",
            state.regs.len(),
            size_of::<kvm_regs>()
        )));
    }
    let regs: kvm_regs = unsafe { std::ptr::read(state.regs.as_ptr() as *const kvm_regs) };
    fd.set_regs(&regs)?;

    // 3. MSRs.
    if !state.msrs.is_empty() {
        let entry_size = size_of::<kvm_msr_entry>();
        if state.msrs.len() % entry_size != 0 {
            return Err(VcpuStateError::BuildMsrs(format!(
                "msrs blob length {} not a multiple of entry size {entry_size}",
                state.msrs.len()
            )));
        }
        let count = state.msrs.len() / entry_size;
        let entries: Vec<kvm_msr_entry> = unsafe {
            std::slice::from_raw_parts(state.msrs.as_ptr() as *const kvm_msr_entry, count)
        }
        .to_vec();
        let msrs = Msrs::from_entries(&entries)
            .map_err(|e| VcpuStateError::BuildMsrs(format!("{e:?}")))?;
        let _written = fd.set_msrs(&msrs)?;
    }

    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
#[allow(unused_variables)]
/// Placeholder for non-x86_64.
pub fn apply(_fd: &(), _state: &VcpuStateData) -> Result<(), VcpuStateError> {
    Ok(())
}
