// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Third-party annotations - annotations defined by other projects or k8s plugins but that can
//! change Kata Containers behaviour.

/// Annotation to enable SGX.
///
/// Hardware-based isolation and memory encryption.
pub const SGX_EPC: &str = "sgx.intel.com/epc";

/// Sandbox snapshot/restore: when present on the sandbox-create OCI spec,
/// the runtime will route the create through the hypervisor's
/// restore-from-snapshot path instead of the normal boot path. The value
/// is the absolute path to a snapshot directory previously written by
/// Sandbox.snapshot (containing the hypervisor's state + config files).
pub const SANDBOX_SNAPSHOT_RESTORE_FROM_PATH: &str = "podsnapshot.aks.io/restore-from-path";
