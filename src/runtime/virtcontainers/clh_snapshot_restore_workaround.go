//go:build linux

// Copyright (c) 2026 The Kata Containers Authors
//
// SPDX-License-Identifier: Apache-2.0
//
// POC-only restore workaround for the vhost-user-fs activate-on-restore hang.
//
// Symptom (observed live on aks-snap-poc-vm running Kata 3.21 + CLH v48):
// during /vm.restore CLH logs progress up to and including
//
//   INFO:vmm/src/device_manager.rs:4283 -- Restoring virtio-pci _virtio-pci-_fs2 resources
//
// and then hangs indefinitely. Tracing under RUST_LOG=trace pins the hang
// inside VirtioPciDevice::new at virtio-devices/src/transport/pci_device.rs:611
// where, on a restored device, CLH calls activate() if the saved state has
// device_activated=true. For vhost-user-fs this triggers
// Fs::activate -> VhostUserCommon::activate -> the full vhost-user
// re-handshake (SET_FEATURES, SET_MEM_TABLE, SET_VRING_NUM, SET_VRING_KICK, ...)
// against the freshly-spawned virtiofsd. virtiofsd accepts the connection
// but has no prior FUSE session state, so the handshake stalls and the
// restore never completes.
//
// The proper fix is virtio-fs migration: source-side virtiofsd dumps its
// FUSE session + inode table to a file, destination-side virtiofsd loads
// it before CLH connects. That work is scoped as Phase C6 of the roadmap
// and will be done once in the Rust runtime.
//
// For the POC we work around the hang by patching the snapshot's
// state.json on the restore side to set
// snapshots.device-manager.snapshots._virtio-pci-_fs2.snapshot_data.state's
// inner `device_activated` field from true to false. CLH then skips the
// activate() call, leaving the PCI device present but disconnected from
// virtiofsd. The guest still has the kataShared mount and will hang on
// any subsequent FUSE op against it; the counter-pod demo workload is
// in-memory only and does not touch the shared FS after boot, so the
// pod resumes and the round-trip can be demonstrated.
//
// This entire file (and its call site in clh.go) is expected to be
// deleted when Phase C6 lands. Search for "POC" or
// rewriteSnapshotStateForNewSandbox to locate the workaround.

package virtcontainers

import (
	"encoding/json"
	"fmt"
	"os"
)

// rewriteSnapshotStateForNewSandbox edits statePath (the CLH snapshot's
// state.json) in place, flipping device_activated=false on the snapshot
// entry for the vhost-user-fs device's PCI transport. The function is
// idempotent and silently no-ops if no _virtio-pci-_fs2 entry is present
// (e.g. a snapshot taken from a sandbox configured without virtio-fs).
//
// The JSON layout we patch (as written by CLH v48):
//
//   {
//     "snapshots": {
//       "device-manager": {
//         "snapshots": {
//           "_virtio-pci-_fs2": {
//             "snapshots": {...},
//             "snapshot_data": {
//               // The "state" field is itself a JSON-encoded string.
//               "state": "{\"device_activated\":true, ...}"
//             }
//           }
//         }
//       }
//     }
//   }
//
// We parse the outer object, drill to the nested "snapshot_data.state"
// string, parse THAT as JSON, set device_activated=false, re-serialise
// the inner state, write the outer object back as a temp file, then
// rename atomically.
func rewriteSnapshotStateForNewSandbox(statePath string) error {
	raw, err := os.ReadFile(statePath)
	if err != nil {
		return fmt.Errorf("read snapshot state.json: %w", err)
	}

	var root map[string]interface{}
	if err := json.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("parse snapshot state.json: %w", err)
	}

	devSnap, ok := drill(root, "snapshots", "device-manager", "snapshots", "_virtio-pci-_fs2", "snapshot_data")
	if !ok {
		// Sandbox had no virtio-fs device; nothing to patch.
		return nil
	}
	devSnapMap, ok := devSnap.(map[string]interface{})
	if !ok {
		return fmt.Errorf("snapshot_data for _virtio-pci-_fs2 is not an object")
	}
	innerJSON, ok := devSnapMap["state"].(string)
	if !ok {
		// CLH always writes a string here; if it's absent or a different
		// type we don't risk silently corrupting the snapshot.
		return fmt.Errorf("snapshot_data.state for _virtio-pci-_fs2 is missing or not a string")
	}

	var innerState map[string]interface{}
	if err := json.Unmarshal([]byte(innerJSON), &innerState); err != nil {
		return fmt.Errorf("parse inner _virtio-pci-_fs2 state: %w", err)
	}

	prev, _ := innerState["device_activated"].(bool)
	if !prev {
		// Already false (idempotent re-restore, or unusual snapshot).
		return nil
	}
	innerState["device_activated"] = false

	patchedInner, err := json.Marshal(innerState)
	if err != nil {
		return fmt.Errorf("re-encode inner _virtio-pci-_fs2 state: %w", err)
	}
	devSnapMap["state"] = string(patchedInner)

	patchedOuter, err := json.Marshal(root)
	if err != nil {
		return fmt.Errorf("re-encode snapshot state.json: %w", err)
	}

	tmp := statePath + ".tmp"
	if err := os.WriteFile(tmp, patchedOuter, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, statePath)
}

// drill walks an unmarshalled JSON tree following the given map keys and
// returns the value at the leaf, or (nil, false) if any intermediate
// node is missing or is not a map.
func drill(root map[string]interface{}, keys ...string) (interface{}, bool) {
	var cur interface{} = root
	for _, k := range keys {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		v, present := m[k]
		if !present {
			return nil, false
		}
		cur = v
	}
	return cur, true
}
