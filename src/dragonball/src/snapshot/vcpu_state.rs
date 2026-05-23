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
use kvm_bindings::{kvm_cpuid_entry2, kvm_msr_entry, kvm_regs, kvm_sregs, Msrs};
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
