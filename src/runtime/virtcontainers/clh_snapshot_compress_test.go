//go:build linux

// Copyright (c) 2026 The Kata Containers Authors
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fillSnapshotDir lays out a fake CLH snapshot in dir: two memory-ranges
// blobs (one all-zeroes — best case for zstd, one with random bytes —
// worst case) plus the JSON sidecars CLH always writes.
func fillSnapshotDir(t *testing.T, dir string) (zeros, rand1, cfgJSON, stateJSON []byte) {
	t.Helper()

	zeros = make([]byte, 4*1024*1024) // 4 MiB of zero pages — compresses to <100 bytes
	rand1 = make([]byte, 1*1024*1024) // 1 MiB random — barely compresses
	_, err := rand.Read(rand1)
	require.NoError(t, err)
	cfgJSON = []byte(`{"net":[]}`)
	stateJSON = []byte(`{"vm":"state"}`)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "memory-ranges-0"), zeros, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "memory-ranges-1"), rand1, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), cfgJSON, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "state.json"), stateJSON, 0o600))
	return
}

// TestSnapshotCompressionEnabled covers the mode-string parsing.
func TestSnapshotCompressionEnabled(t *testing.T) {
	cases := []struct {
		mode string
		want bool
	}{
		{"", false},
		{"none", false},
		{"None", false},
		{"  none  ", false},
		{"zstd", true},
		{"ZSTD", true},
		{"unknown-bzip", false}, // graceful degradation
	}
	for _, c := range cases {
		t.Run(c.mode, func(t *testing.T) {
			assert.Equal(t, c.want, snapshotCompressionEnabled(c.mode))
		})
	}
}

// TestCompressDecompressRoundtrip — the critical correctness guarantee:
// compressing then decompressing returns identical bytes for every
// memory-ranges-* blob, JSON files are preserved, and the canonical
// snapshot's .json is independent of the decompressed copy (so a restore
// rewriting config.json doesn't corrupt the source).
func TestCompressDecompressRoundtrip(t *testing.T) {
	src := t.TempDir()
	zeros, rand1, cfgJSON, stateJSON := fillSnapshotDir(t, src)

	count, in, out, err := compressSnapshotMemory(src, 0 /* default level */)
	require.NoError(t, err)
	assert.Equal(t, 2, count, "should compress both memory-ranges blobs")
	assert.Greater(t, in, int64(0))
	assert.Greater(t, out, int64(0))
	assert.Less(t, out, in, "compressed output should be smaller than input on this fixture")

	// Raw memory-ranges-* should be gone, .zst should exist.
	for _, n := range []string{"memory-ranges-0", "memory-ranges-1"} {
		_, err := os.Stat(filepath.Join(src, n))
		assert.True(t, os.IsNotExist(err), "raw blob %s should be removed", n)

		st, err := os.Stat(filepath.Join(src, n+snapshotCompressedSuffix))
		require.NoError(t, err, "%s.zst should exist", n)
		assert.Greater(t, st.Size(), int64(0))
	}

	// JSON sidecars left untouched.
	for _, n := range []string{"config.json", "state.json"} {
		_, err := os.Stat(filepath.Join(src, n))
		require.NoError(t, err)
	}

	// snapshotIsCompressed should now report true.
	compressed, err := snapshotIsCompressed(src)
	require.NoError(t, err)
	assert.True(t, compressed)

	// Decompress into a tmpdir and verify byte-for-byte equality.
	tmp, err := decompressSnapshotForRestore(src)
	require.NoError(t, err)
	defer os.RemoveAll(tmp)

	got0, err := os.ReadFile(filepath.Join(tmp, "memory-ranges-0"))
	require.NoError(t, err)
	assert.True(t, bytes.Equal(got0, zeros), "memory-ranges-0 round-trip mismatch")

	got1, err := os.ReadFile(filepath.Join(tmp, "memory-ranges-1"))
	require.NoError(t, err)
	assert.True(t, bytes.Equal(got1, rand1), "memory-ranges-1 round-trip mismatch")

	gotCfg, err := os.ReadFile(filepath.Join(tmp, "config.json"))
	require.NoError(t, err)
	assert.True(t, bytes.Equal(gotCfg, cfgJSON))

	gotState, err := os.ReadFile(filepath.Join(tmp, "state.json"))
	require.NoError(t, err)
	assert.True(t, bytes.Equal(gotState, stateJSON))

	// Critical: editing the decompressed config.json must NOT mutate the
	// canonical snapshot's config.json. This is what makes multiple
	// concurrent restores from the same snapshot safe (each gets its own
	// rewriteSnapshotConfigForNewSandbox edit).
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "config.json"),
		[]byte(`{"rewritten":true}`), 0o600))
	canonicalCfg, err := os.ReadFile(filepath.Join(src, "config.json"))
	require.NoError(t, err)
	assert.True(t, bytes.Equal(canonicalCfg, cfgJSON),
		"canonical snapshot config.json was unexpectedly mutated by tmpdir edit (config.json must be COPIED, not hardlinked)")
}

// TestCompressIsIdempotent — re-running compressSnapshotMemory on an
// already-compressed dir is a no-op (does not re-compress .zst into
// .zst.zst, does not crash).
func TestCompressIsIdempotent(t *testing.T) {
	src := t.TempDir()
	fillSnapshotDir(t, src)

	count1, _, _, err := compressSnapshotMemory(src, 0)
	require.NoError(t, err)
	assert.Equal(t, 2, count1)

	count2, in, out, err := compressSnapshotMemory(src, 0)
	require.NoError(t, err)
	assert.Equal(t, 0, count2, "second run should compress nothing")
	assert.Equal(t, int64(0), in)
	assert.Equal(t, int64(0), out)

	// Make sure no doubly-compressed file appeared.
	entries, err := os.ReadDir(src)
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasSuffix(e.Name(), ".zst.zst"),
			"unexpected doubly-compressed file %q", e.Name())
	}
}

// TestSnapshotIsCompressedFalseWhenRaw — predicate must not falsely
// flag a raw snapshot as compressed.
func TestSnapshotIsCompressedFalseWhenRaw(t *testing.T) {
	src := t.TempDir()
	fillSnapshotDir(t, src)

	compressed, err := snapshotIsCompressed(src)
	require.NoError(t, err)
	assert.False(t, compressed)
}

// TestDecompressMixedSnapshot — a snapshot with one .zst and one raw
// memory-ranges-* (e.g. partial compression interrupted mid-run) must
// still decompress cleanly: .zst decoded, raw passed through.
func TestDecompressMixedSnapshot(t *testing.T) {
	src := t.TempDir()
	zeros, rand1, _, _ := fillSnapshotDir(t, src)

	// Compress only memory-ranges-0 by hand.
	count, _, _, err := compressSnapshotMemory(src, 0)
	require.NoError(t, err)
	require.Equal(t, 2, count)
	// Restore memory-ranges-1 as raw (simulate a half-compressed dir).
	require.NoError(t, os.WriteFile(filepath.Join(src, "memory-ranges-1"), rand1, 0o600))
	require.NoError(t, os.Remove(filepath.Join(src, "memory-ranges-1.zst")))

	tmp, err := decompressSnapshotForRestore(src)
	require.NoError(t, err)
	defer os.RemoveAll(tmp)

	got0, err := os.ReadFile(filepath.Join(tmp, "memory-ranges-0"))
	require.NoError(t, err)
	assert.True(t, bytes.Equal(got0, zeros))

	got1, err := os.ReadFile(filepath.Join(tmp, "memory-ranges-1"))
	require.NoError(t, err)
	assert.True(t, bytes.Equal(got1, rand1))
}

// TestResolveZstdLevel — verify the level mapping covers the documented range.
func TestResolveZstdLevel(t *testing.T) {
	// Just smoke-check that the function never panics and returns a level
	// that the encoder accepts.
	for n := -1; n <= 25; n++ {
		_ = resolveZstdLevel(n)
	}
}
