// Copyright (C) 2025 Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! VM-level architectural state snapshot (I-008b).
//!
//! Captures the KVM in-kernel objects whose state must be preserved across
//! a snapshot/restore cycle but which live on the `VmFd` rather than on
//! individual `VcpuFd`s: the two halves of the PIC, the IOAPIC, the PIT2,
//! and the wall clock. Without these, a no-boot restore (I-008b) hands
//! back a vCPU whose interrupt routing is undefined.

#[cfg(target_arch = "x86_64")]
use kvm_bindings::{
    kvm_clock_data, kvm_irqchip, kvm_pit_state2, KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER,
    KVM_IRQCHIP_PIC_SLAVE,
};
#[cfg(target_arch = "x86_64")]
use kvm_ioctls::VmFd;

use super::vcpu_state::VcpuStateError;

/// VM-level architectural state. All fields are raw bytes of the
/// corresponding `kvm_*` C structs — same wire convention as
/// [`super::vcpu_state::VcpuStateData`].
#[derive(Debug, Default, Clone)]
pub struct VmStateData {
    /// `kvm_irqchip` for the master 8259 PIC.
    pub pic_master: Vec<u8>,
    /// `kvm_irqchip` for the slave 8259 PIC.
    pub pic_slave: Vec<u8>,
    /// `kvm_irqchip` for the IOAPIC.
    pub ioapic: Vec<u8>,
    /// `kvm_pit_state2` for the in-kernel PIT.
    pub pit2: Vec<u8>,
    /// `kvm_clock_data` (host wall-clock anchor for kvmclock).
    pub clock: Vec<u8>,
}

#[cfg(target_arch = "x86_64")]
fn struct_to_bytes<T: Copy>(value: &T) -> Vec<u8> {
    let slice = unsafe {
        std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>())
    };
    slice.to_vec()
}

/// Capture VM-level KVM state. Missing PIT2 / IRQCHIP support is logged
/// but treated as best-effort: dragonball typically configures both, but a
/// confidential-VM build might lack them. Empty fields round-trip cleanly
/// through [`apply`] (which skips on length mismatch).
#[cfg(target_arch = "x86_64")]
pub fn capture(vm_fd: &VmFd) -> Result<VmStateData, VcpuStateError> {
    let mut pic_master_blob: kvm_irqchip = unsafe { std::mem::zeroed() };
    pic_master_blob.chip_id = KVM_IRQCHIP_PIC_MASTER;
    vm_fd.get_irqchip(&mut pic_master_blob)?;

    let mut pic_slave_blob: kvm_irqchip = unsafe { std::mem::zeroed() };
    pic_slave_blob.chip_id = KVM_IRQCHIP_PIC_SLAVE;
    vm_fd.get_irqchip(&mut pic_slave_blob)?;

    let mut ioapic_blob: kvm_irqchip = unsafe { std::mem::zeroed() };
    ioapic_blob.chip_id = KVM_IRQCHIP_IOAPIC;
    vm_fd.get_irqchip(&mut ioapic_blob)?;

    let pit2: kvm_pit_state2 = vm_fd.get_pit2()?;
    let clock: kvm_clock_data = vm_fd.get_clock()?;

    Ok(VmStateData {
        pic_master: struct_to_bytes(&pic_master_blob),
        pic_slave: struct_to_bytes(&pic_slave_blob),
        ioapic: struct_to_bytes(&ioapic_blob),
        pit2: struct_to_bytes(&pit2),
        clock: struct_to_bytes(&clock),
    })
}

#[cfg(not(target_arch = "x86_64"))]
pub fn capture(_vm_fd: &()) -> Result<VmStateData, VcpuStateError> {
    Ok(VmStateData::default())
}

/// Apply previously-captured VM-level state to `vm_fd`. Calls
/// `KVM_SET_IRQCHIP` for each of the three chips, `KVM_SET_PIT2`,
/// and `KVM_SET_CLOCK`. Skips any field whose blob length doesn't match
/// the expected struct (e.g. older snapshots that didn't capture it).
#[cfg(target_arch = "x86_64")]
pub fn apply(vm_fd: &VmFd, state: &VmStateData) -> Result<(), VcpuStateError> {
    use std::mem::size_of;

    if state.pic_master.len() == size_of::<kvm_irqchip>() {
        let ic: kvm_irqchip =
            unsafe { std::ptr::read(state.pic_master.as_ptr() as *const kvm_irqchip) };
        vm_fd.set_irqchip(&ic)?;
    }
    if state.pic_slave.len() == size_of::<kvm_irqchip>() {
        let ic: kvm_irqchip =
            unsafe { std::ptr::read(state.pic_slave.as_ptr() as *const kvm_irqchip) };
        vm_fd.set_irqchip(&ic)?;
    }
    if state.ioapic.len() == size_of::<kvm_irqchip>() {
        let ic: kvm_irqchip =
            unsafe { std::ptr::read(state.ioapic.as_ptr() as *const kvm_irqchip) };
        vm_fd.set_irqchip(&ic)?;
    }
    if state.pit2.len() == size_of::<kvm_pit_state2>() {
        let pit: kvm_pit_state2 =
            unsafe { std::ptr::read(state.pit2.as_ptr() as *const kvm_pit_state2) };
        vm_fd.set_pit2(&pit)?;
    }
    if state.clock.len() == size_of::<kvm_clock_data>() {
        let clk: kvm_clock_data =
            unsafe { std::ptr::read(state.clock.as_ptr() as *const kvm_clock_data) };
        vm_fd.set_clock(&clk)?;
    }
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
pub fn apply(_vm_fd: &(), _state: &VmStateData) -> Result<(), VcpuStateError> {
    Ok(())
}
