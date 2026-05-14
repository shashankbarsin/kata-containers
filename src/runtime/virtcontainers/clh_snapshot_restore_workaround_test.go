//go:build linux

// Copyright (c) 2026 The Kata Containers Authors
//
// SPDX-License-Identifier: Apache-2.0

package virtcontainers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeStateJSON returns a CLH-shaped state.json containing a
// _virtio-pci-_fs2 entry whose snapshot_data.state is a JSON-string
// with device_activated set to the requested value. Extra siblings are
// included so the helper has to navigate a realistic tree, not a stub.
func fakeStateJSON(t *testing.T, fsActivated bool) []byte {
	t.Helper()
	inner := map[string]interface{}{
		"device_activated":   fsActivated,
		"queues":             []interface{}{},
		"interrupt_status":   0,
		"cap_pci_cfg_offset": 134,
		"cap_pci_cfg":        []interface{}{},
	}
	innerBytes, err := json.Marshal(inner)
	require.NoError(t, err)

	root := map[string]interface{}{
		"snapshots": map[string]interface{}{
			"device-manager": map[string]interface{}{
				"snapshots": map[string]interface{}{
					"_virtio-pci-_disk0": map[string]interface{}{
						"snapshot_data": map[string]interface{}{
							"state": `{"device_activated":true,"id":"disk0"}`,
						},
					},
					"_virtio-pci-_fs2": map[string]interface{}{
						"snapshots": map[string]interface{}{},
						"snapshot_data": map[string]interface{}{
							"state": string(innerBytes),
						},
					},
				},
			},
		},
	}
	out, err := json.Marshal(root)
	require.NoError(t, err)
	return out
}

// extractFsDeviceActivated decodes a state.json blob and returns the
// device_activated flag inside _virtio-pci-_fs2's nested state string.
func extractFsDeviceActivated(t *testing.T, raw []byte) bool {
	t.Helper()
	var root map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &root))

	leaf, ok := drill(root, "snapshots", "device-manager", "snapshots", "_virtio-pci-_fs2", "snapshot_data")
	require.True(t, ok, "missing _virtio-pci-_fs2 snapshot_data")
	leafMap := leaf.(map[string]interface{})
	innerStr := leafMap["state"].(string)

	var inner map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(innerStr), &inner))
	v, _ := inner["device_activated"].(bool)
	return v
}

func writeStateFile(t *testing.T, body []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	require.NoError(t, os.WriteFile(p, body, 0o600))
	return p
}

func TestRewriteSnapshotStateFlipsFsActivated(t *testing.T) {
	state := fakeStateJSON(t, true /* activated */)
	statePath := writeStateFile(t, state)

	require.NoError(t, rewriteSnapshotStateForNewSandbox(statePath))

	patched, err := os.ReadFile(statePath)
	require.NoError(t, err)
	assert.False(t, extractFsDeviceActivated(t, patched),
		"_virtio-pci-_fs2.device_activated should have been flipped to false")
}

func TestRewriteSnapshotStateIdempotentWhenAlreadyFalse(t *testing.T) {
	state := fakeStateJSON(t, false /* already inactive */)
	statePath := writeStateFile(t, state)

	require.NoError(t, rewriteSnapshotStateForNewSandbox(statePath))

	patched, err := os.ReadFile(statePath)
	require.NoError(t, err)
	assert.False(t, extractFsDeviceActivated(t, patched),
		"already-false should remain false")
}

func TestRewriteSnapshotStateMissingFsIsNoOp(t *testing.T) {
	root := map[string]interface{}{
		"snapshots": map[string]interface{}{
			"device-manager": map[string]interface{}{
				"snapshots": map[string]interface{}{
					"_virtio-pci-_disk0": map[string]interface{}{
						"snapshot_data": map[string]interface{}{
							"state": `{"device_activated":true,"id":"disk0"}`,
						},
					},
				},
			},
		},
	}
	body, err := json.Marshal(root)
	require.NoError(t, err)
	statePath := writeStateFile(t, body)

	// Must not return an error; must leave the file byte-equal.
	require.NoError(t, rewriteSnapshotStateForNewSandbox(statePath))

	after, err := os.ReadFile(statePath)
	require.NoError(t, err)
	assert.Equal(t, body, after,
		"state.json without _virtio-pci-_fs2 should be left untouched")
}

func TestRewriteSnapshotStateRejectsMalformedJSON(t *testing.T) {
	statePath := writeStateFile(t, []byte("not json at all"))
	err := rewriteSnapshotStateForNewSandbox(statePath)
	require.Error(t, err)
	assert.True(t,
		strings.Contains(err.Error(), "parse snapshot state.json"),
		"want a parse error, got: %v", err)
}

func TestRewriteSnapshotStateRejectsBadInnerState(t *testing.T) {
	root := map[string]interface{}{
		"snapshots": map[string]interface{}{
			"device-manager": map[string]interface{}{
				"snapshots": map[string]interface{}{
					"_virtio-pci-_fs2": map[string]interface{}{
						"snapshot_data": map[string]interface{}{
							"state": 12345, // wrong type
						},
					},
				},
			},
		},
	}
	body, err := json.Marshal(root)
	require.NoError(t, err)
	statePath := writeStateFile(t, body)

	err = rewriteSnapshotStateForNewSandbox(statePath)
	require.Error(t, err)
}

func TestRewriteSnapshotStatePreservesOtherFields(t *testing.T) {
	// Build a richer fixture: more fields in the inner state, more
	// siblings in device-manager.snapshots — assert NOTHING else
	// changes.
	inner := map[string]interface{}{
		"device_activated":   true,
		"queues":             []interface{}{map[string]interface{}{"size": 1024.0, "ready": true}},
		"interrupt_status":   42.0,
		"cap_pci_cfg_offset": 134.0,
		"cap_pci_cfg":        []interface{}{1.0, 2.0, 3.0},
	}
	innerBytes, _ := json.Marshal(inner)

	root := map[string]interface{}{
		"version": 1.0,
		"snapshots": map[string]interface{}{
			"device-manager": map[string]interface{}{
				"snapshots": map[string]interface{}{
					"_virtio-pci-_fs2": map[string]interface{}{
						"snapshot_data": map[string]interface{}{
							"state": string(innerBytes),
						},
					},
				},
			},
			"vm": map[string]interface{}{"some": "data"},
		},
	}
	body, _ := json.Marshal(root)
	statePath := writeStateFile(t, body)

	require.NoError(t, rewriteSnapshotStateForNewSandbox(statePath))

	patched, err := os.ReadFile(statePath)
	require.NoError(t, err)

	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(patched, &got))
	assert.Equal(t, 1.0, got["version"])
	assert.Equal(t, map[string]interface{}{"some": "data"}, got["snapshots"].(map[string]interface{})["vm"])

	leaf, ok := drill(got, "snapshots", "device-manager", "snapshots", "_virtio-pci-_fs2", "snapshot_data")
	require.True(t, ok)
	innerStr := leaf.(map[string]interface{})["state"].(string)

	var gotInner map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(innerStr), &gotInner))
	assert.Equal(t, false, gotInner["device_activated"],
		"device_activated must be flipped to false")
	assert.Equal(t, 42.0, gotInner["interrupt_status"],
		"other inner fields must be preserved verbatim")
	assert.Equal(t, 134.0, gotInner["cap_pci_cfg_offset"])
}
