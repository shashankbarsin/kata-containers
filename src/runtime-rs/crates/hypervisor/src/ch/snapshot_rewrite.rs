// Copyright (c) 2026 The Kata Containers Authors
//
// SPDX-License-Identifier: Apache-2.0
//
// AKS Pod Snapshot POC (Phase C4.2): port of the Go runtime's snapshot
// rewrite helpers from src/runtime/virtcontainers/clh.go and
// clh_snapshot_restore_workaround.go.
//
// Two distinct rewrites are applied to a CLH snapshot directory before it
// is handed to `cloud-hypervisor --restore source_url=file://...`:
//
//   1. config.json: CLH bakes absolute /run/vc/vm/<old-sandbox-id>/ paths
//      for sockets it has to bind/connect (vsock, virtiofsd). On the
//      destination sandbox those paths point at a different runtime dir
//      (because the new sandbox has a different id), so we string-replace
//      the old id with the new one. The substitution is purely textual
//      on the "/run/vc/vm/<id>/" prefix.
//
//   2. state.json: the v48 cloud-hypervisor binary used by Kata 3.21 hangs
//      indefinitely if a restored vhost-user-fs PCI device has its saved
//      state's device_activated=true (CLH re-handshakes with virtiofsd
//      while virtiofsd has no FUSE session, and the handshake stalls).
//      As a POC workaround we flip the nested device_activated boolean
//      under
//        snapshots.device-manager.snapshots._virtio-pci-_fs2.snapshot_data.state
//      to false. The proper fix is virtio-fs migration in Phase C6; this
//      whole module's state-side rewrite is expected to be deleted when
//      that lands.
//
// `read_snapshot_net_ids` parses the `net` section of config.json and
// returns each device's id + number of fds (the snapshot always writes
// fds: [-1]-style placeholders, so we just need the slice length). The
// restore launch consumes this to map sandbox tap fds to snapshot device
// ids in declaration order.

use anyhow::{anyhow, Context, Result};
use std::path::Path;

/// One net device declared in a CLH snapshot's config.json, in declaration
/// order. `num_fds` is the number of file descriptors the original device
/// had (CLH writes the length but blanks the values to -1 in the snapshot).
//
// AKS Pod Snapshot POC: read_snapshot_net_ids is the API the future restore
// orchestrator (Phase C5+) will call to learn which (id, num_fds) tuples
// to pass to CloudHypervisor::set_restore_net_fds. It is unused inside the
// hypervisor crate today, so silence the dead-code lint until that lands.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SnapshotNetId {
    pub(crate) id: String,
    pub(crate) num_fds: usize,
}

/// Parses the `net` array of a CLH snapshot config.json and returns the
/// per-device (id, num_fds) tuples in declaration order. CLH's /vm.restore
/// requires this mapping so it can re-attach the destination sandbox's
/// tap fds (which are inherited via `--restore net_fds=[id@fd,...]`).
#[allow(dead_code)]
pub(crate) fn read_snapshot_net_ids(config_path: &Path) -> Result<Vec<SnapshotNetId>> {
    let data = std::fs::read(config_path)
        .with_context(|| format!("reading snapshot config {}", config_path.display()))?;
    let v: serde_json::Value = serde_json::from_slice(&data)
        .with_context(|| format!("parsing snapshot config {}", config_path.display()))?;

    let nets = match v.get("net") {
        Some(serde_json::Value::Array(arr)) => arr,
        Some(serde_json::Value::Null) | None => return Ok(Vec::new()),
        Some(other) => {
            return Err(anyhow!(
                "snapshot config {} has `net` of unexpected type {:?}",
                config_path.display(),
                other
            ));
        }
    };

    let mut out = Vec::with_capacity(nets.len());
    for (i, n) in nets.iter().enumerate() {
        let id = n
            .get("id")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("snapshot config net[{i}] missing string `id`"))?
            .to_string();
        let num_fds = match n.get("fds") {
            Some(serde_json::Value::Array(arr)) => arr.len(),
            // Snapshots taken from a config that supplied no fds field at all.
            Some(serde_json::Value::Null) | None => 0,
            Some(other) => {
                return Err(anyhow!(
                    "snapshot config net[{i}] `fds` is not an array: {:?}",
                    other
                ));
            }
        };
        out.push(SnapshotNetId { id, num_fds });
    }
    Ok(out)
}

/// Rewrites `config_path` in place, replacing every occurrence of
/// `/run/vc/vm/<old-sandbox-id>/` with `/run/vc/vm/<new_id>/`. CLH bakes
/// absolute paths for sandbox-local sockets (vsock, virtiofsd) into the
/// snapshot config; without this rewrite /vm.restore would bind/connect
/// against the original sandbox's runtime dir.
///
/// The substitution is purely textual on the `/run/vc/vm/` prefix. If the
/// snapshot contains no such paths (e.g. a sandbox without virtio-fs or a
/// custom vsock path) the function is a no-op. If the embedded id already
/// matches `new_id` the function is also a no-op.
pub(crate) fn rewrite_snapshot_config_for_new_sandbox(
    config_path: &Path,
    new_id: &str,
) -> Result<()> {
    let data = std::fs::read(config_path)
        .with_context(|| format!("reading snapshot config {}", config_path.display()))?;

    const VM_DIR_PREFIX: &[u8] = b"/run/vc/vm/";

    let idx = match find_subslice(&data, VM_DIR_PREFIX) {
        Some(i) => i,
        None => return Ok(()),
    };
    let after = &data[idx + VM_DIR_PREFIX.len()..];
    // The sandbox id ends at the next `/` or `"`.
    let end = after
        .iter()
        .position(|b| *b == b'/' || *b == b'"')
        .ok_or_else(|| anyhow!("malformed sandbox-id in snapshot config {}", config_path.display()))?;
    if end == 0 {
        return Err(anyhow!(
            "malformed sandbox-id in snapshot config {}",
            config_path.display()
        ));
    }
    let old_id = std::str::from_utf8(&after[..end])
        .with_context(|| format!("snapshot config {} has non-UTF8 sandbox-id", config_path.display()))?;
    if old_id == new_id {
        return Ok(());
    }

    let needle = format!("/run/vc/vm/{old_id}/");
    let replacement = format!("/run/vc/vm/{new_id}/");
    let patched = replace_bytes(&data, needle.as_bytes(), replacement.as_bytes());

    let tmp = config_path.with_extension("json.tmp");
    std::fs::write(&tmp, &patched)
        .with_context(|| format!("writing patched snapshot config {}", tmp.display()))?;
    std::fs::rename(&tmp, config_path).with_context(|| {
        format!(
            "renaming patched snapshot config {} -> {}",
            tmp.display(),
            config_path.display()
        )
    })?;
    Ok(())
}

/// POC workaround (Phase C4.2 + C6 backstop): edits state.json in place,
/// flipping the inner `device_activated` field on the snapshot entry for
/// the vhost-user-fs PCI device from true to false. This sidesteps the
/// hang where CLH on /vm.restore tries to re-handshake virtiofsd while
/// virtiofsd has no FUSE session.
///
/// Idempotent: no-op if the snapshot has no `_virtio-pci-_fs2` entry, or
/// if `device_activated` is already false.
///
/// This entire helper goes away once Phase C6 (virtio-fs migration) lands
/// in the Rust runtime.
pub(crate) fn rewrite_snapshot_state_for_new_sandbox(state_path: &Path) -> Result<()> {
    let raw = std::fs::read(state_path)
        .with_context(|| format!("reading snapshot state {}", state_path.display()))?;
    let mut root: serde_json::Value = serde_json::from_slice(&raw)
        .with_context(|| format!("parsing snapshot state {}", state_path.display()))?;

    let snap_data = match root
        .pointer_mut("/snapshots/device-manager/snapshots/_virtio-pci-_fs2/snapshot_data")
    {
        Some(v) if v.is_object() => v,
        // Sandbox had no virtio-fs device; nothing to patch.
        _ => return Ok(()),
    };
    let snap_obj = snap_data.as_object_mut().expect("checked is_object above");

    let inner_str = match snap_obj.get("state") {
        Some(serde_json::Value::String(s)) => s.clone(),
        // CLH always writes this as a JSON-encoded string. If it's absent
        // or a different type we'd rather error than silently corrupt the
        // snapshot.
        _ => {
            return Err(anyhow!(
                "snapshot state {} has snapshot_data.state missing or not a string",
                state_path.display()
            ));
        }
    };

    let mut inner: serde_json::Value = serde_json::from_str(&inner_str).with_context(|| {
        format!(
            "parsing inner _virtio-pci-_fs2 state in {}",
            state_path.display()
        )
    })?;
    let inner_obj = inner.as_object_mut().ok_or_else(|| {
        anyhow!(
            "inner _virtio-pci-_fs2 state in {} is not a JSON object",
            state_path.display()
        )
    })?;
    let prev = inner_obj
        .get("device_activated")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !prev {
        return Ok(());
    }
    inner_obj.insert("device_activated".to_string(), serde_json::Value::Bool(false));

    let patched_inner = serde_json::to_string(&inner)
        .context("re-encoding inner _virtio-pci-_fs2 state")?;
    snap_obj.insert(
        "state".to_string(),
        serde_json::Value::String(patched_inner),
    );

    let patched_outer = serde_json::to_vec(&root).context("re-encoding snapshot state")?;
    let tmp = state_path.with_extension("json.tmp");
    std::fs::write(&tmp, &patched_outer)
        .with_context(|| format!("writing patched snapshot state {}", tmp.display()))?;
    std::fs::rename(&tmp, state_path).with_context(|| {
        format!(
            "renaming patched snapshot state {} -> {}",
            tmp.display(),
            state_path.display()
        )
    })?;
    Ok(())
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn replace_bytes(hay: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if i + from.len() <= hay.len() && &hay[i..i + from.len()] == from {
            out.extend_from_slice(to);
            i += from.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_snapshot_net_ids_parses_id_and_fd_count() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            br#"{"net":[{"id":"_net0","fds":[-1]},{"id":"_net1","fds":[-1,-1]}]}"#,
        )
        .unwrap();
        let got = read_snapshot_net_ids(tmp.path()).unwrap();
        assert_eq!(
            got,
            vec![
                SnapshotNetId {
                    id: "_net0".into(),
                    num_fds: 1
                },
                SnapshotNetId {
                    id: "_net1".into(),
                    num_fds: 2
                },
            ]
        );
    }

    #[test]
    fn read_snapshot_net_ids_missing_net_is_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"{}").unwrap();
        let got = read_snapshot_net_ids(tmp.path()).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn rewrite_config_swaps_sandbox_id() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            br#"{"vsock":{"socket":"/run/vc/vm/old-sandbox/clh.sock"}}"#,
        )
        .unwrap();
        rewrite_snapshot_config_for_new_sandbox(tmp.path(), "new-sandbox").unwrap();
        let after = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(
            after.contains("/run/vc/vm/new-sandbox/clh.sock"),
            "after={}",
            after
        );
        assert!(!after.contains("/run/vc/vm/old-sandbox/"));
    }

    #[test]
    fn rewrite_config_no_per_sandbox_paths_is_noop() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let original = br#"{"cpus":{"boot_vcpus":1}}"#;
        std::fs::write(tmp.path(), original).unwrap();
        rewrite_snapshot_config_for_new_sandbox(tmp.path(), "new-sandbox").unwrap();
        assert_eq!(std::fs::read(tmp.path()).unwrap(), original);
    }

    #[test]
    fn rewrite_state_flips_fs2_device_activated() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let inner = r#"{"device_activated":true,"foo":1}"#;
        let outer = serde_json::json!({
            "snapshots": {
                "device-manager": {
                    "snapshots": {
                        "_virtio-pci-_fs2": {
                            "snapshot_data": { "state": inner }
                        }
                    }
                }
            }
        });
        std::fs::write(tmp.path(), serde_json::to_vec(&outer).unwrap()).unwrap();
        rewrite_snapshot_state_for_new_sandbox(tmp.path()).unwrap();

        let after: serde_json::Value =
            serde_json::from_slice(&std::fs::read(tmp.path()).unwrap()).unwrap();
        let inner_str = after
            .pointer("/snapshots/device-manager/snapshots/_virtio-pci-_fs2/snapshot_data/state")
            .unwrap()
            .as_str()
            .unwrap();
        let inner_v: serde_json::Value = serde_json::from_str(inner_str).unwrap();
        assert_eq!(inner_v["device_activated"], serde_json::Value::Bool(false));
        assert_eq!(inner_v["foo"], serde_json::json!(1));
    }

    #[test]
    fn rewrite_state_no_fs_device_is_noop() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let outer = br#"{"snapshots":{"device-manager":{"snapshots":{}}}}"#;
        std::fs::write(tmp.path(), outer).unwrap();
        rewrite_snapshot_state_for_new_sandbox(tmp.path()).unwrap();
        assert_eq!(std::fs::read(tmp.path()).unwrap(), outer);
    }
}
