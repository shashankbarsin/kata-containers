//go:build linux

// Copyright (c) 2026 The Kata Containers Authors
//
// SPDX-License-Identifier: Apache-2.0
//
// Snapshot bulk-memory compression for the Cloud Hypervisor backend.
//
// Cloud Hypervisor's /vm.snapshot writes a directory containing config.json,
// state.json, and one or more memory-ranges-* blobs. The blobs hold the
// guest's full RAM and dominate snapshot size — typically 200–4096 MiB,
// versus ~10 KiB for the JSON files.
//
// On a kata-clh sandbox with reclaim_guest_freed_memory + a 256 MiB floor,
// the actual blob ranges from a few tens of MiB (idle pause) to a few
// hundred MiB (live workload). zstd at level 3 yields a ~2–3x reduction
// on idle guest RAM (lots of zero pages and identical kernel/agent pages),
// so a 256 MiB blob shrinks to ~60–110 MiB on disk.
//
// We don't ask Cloud Hypervisor to write or read a compressed file; CLH
// only speaks file:// (raw bytes). Instead:
//   1. After SnapshotVM completes, walk the destination dir and replace
//      each memory-ranges-* file with <name>.zst, removing the original.
//      Performed inline on the snapshot path.
//   2. Before /vm.restore, if any .zst file is present, decompress every
//      file (memory and JSON) into a sibling tmpdir and point CLH at the
//      tmpdir as source_url. The tmpdir is cleaned up after restore.
//
// JSON files are not compressed (already tiny) but they are hardlinked into
// the decompressed tmpdir so config.json rewriting + state.json access still
// hit the same content.

package virtcontainers

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

const (
	// snapshotCompressionZstd is the only non-empty compression string we
	// currently understand. It maps to zstd-level <SnapshotCompressionLevel>.
	snapshotCompressionZstd = "zstd"

	// snapshotCompressedSuffix is appended to memory-ranges-* files in
	// the on-disk snapshot dir when compression is in effect. Chosen to
	// match the de-facto zstd extension so external tooling (zstd CLI,
	// container registries treating it as gzip-like) interoperates.
	snapshotCompressedSuffix = ".zst"

	// snapshotMemoryRangePrefix is the filename prefix Cloud Hypervisor
	// uses for guest RAM blobs in a snapshot directory. Stable across CLH
	// v25+ but may change in future major releases — single source of
	// truth here.
	snapshotMemoryRangePrefix = "memory-ranges-"
)

// snapshotCompressionEnabled returns true when the configured compression
// string is a non-empty, non-"none" value we recognise.
func snapshotCompressionEnabled(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "none":
		return false
	case snapshotCompressionZstd:
		return true
	default:
		// Unknown modes get treated as "off" — we'd rather degrade
		// gracefully than fail the snapshot. The caller emits a warning.
		return false
	}
}

// resolveZstdLevel maps SnapshotCompressionLevel (0..22, 0 == default)
// onto klauspost/compress/zstd.EncoderLevel. We clamp to the supported
// range and fall back to SpeedDefault on out-of-range input.
func resolveZstdLevel(n int) zstd.EncoderLevel {
	switch {
	case n <= 0:
		return zstd.SpeedDefault // ~level 3
	case n == 1:
		return zstd.SpeedFastest
	case n <= 7:
		return zstd.SpeedDefault
	case n <= 11:
		return zstd.SpeedBetterCompression
	default:
		return zstd.SpeedBestCompression
	}
}

// compressSnapshotMemory walks dir for files matching memory-ranges-* and
// rewrites each as <orig>.zst (klauspost/compress/zstd, streaming). On
// success the original is removed; on any error the partial .zst is
// removed so re-running compress is safe.
//
// Returns (numCompressed, totalBytesIn, totalBytesOut, err).
func compressSnapshotMemory(dir string, level int) (int, int64, int64, error) {
	zlevel := resolveZstdLevel(level)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("read snapshot dir %q: %w", dir, err)
	}

	var (
		count    int
		bytesIn  int64
		bytesOut int64
	)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, snapshotMemoryRangePrefix) {
			continue
		}
		if strings.HasSuffix(name, snapshotCompressedSuffix) {
			// Already compressed — idempotent re-run.
			continue
		}
		src := filepath.Join(dir, name)
		dst := src + snapshotCompressedSuffix

		in, out, err := compressFile(src, dst, zlevel)
		if err != nil {
			// Best-effort cleanup so the dir doesn't end up with both
			// raw and partially-written .zst.
			_ = os.Remove(dst)
			return count, bytesIn, bytesOut, fmt.Errorf("compress %s: %w", name, err)
		}
		// Remove the raw blob only after the .zst is fully written and
		// fsynced — otherwise a crash between Remove and the .zst close
		// would leave a corrupt snapshot.
		if err := os.Remove(src); err != nil {
			_ = os.Remove(dst)
			return count, bytesIn, bytesOut, fmt.Errorf("remove raw %s: %w", name, err)
		}
		count++
		bytesIn += in
		bytesOut += out
	}
	return count, bytesIn, bytesOut, nil
}

// compressFile streams src through a zstd encoder into dst. The dst is
// fsynced before close to make the compression durable.
func compressFile(src, dst string, level zstd.EncoderLevel) (int64, int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, 0, err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, 0, err
	}
	// Track close errors so we don't silently lose data on a broken disk.
	defer func() { _ = out.Close() }()

	enc, err := zstd.NewWriter(out, zstd.WithEncoderLevel(level))
	if err != nil {
		return 0, 0, err
	}

	bytesIn, err := io.Copy(enc, in)
	if err != nil {
		_ = enc.Close()
		return bytesIn, 0, err
	}
	if err := enc.Close(); err != nil {
		return bytesIn, 0, err
	}
	if err := out.Sync(); err != nil {
		return bytesIn, 0, err
	}
	stat, err := out.Stat()
	if err != nil {
		return bytesIn, 0, err
	}
	return bytesIn, stat.Size(), nil
}

// snapshotIsCompressed reports whether dir contains at least one
// memory-ranges-*.zst file. Used by the restore path to decide whether
// to run the decompress step.
func snapshotIsCompressed(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, snapshotMemoryRangePrefix) && strings.HasSuffix(n, snapshotCompressedSuffix) {
			return true, nil
		}
	}
	return false, nil
}

// decompressSnapshotForRestore materialises a sibling tmp directory
// containing decompressed memory-ranges-* alongside copies of the JSON
// files (config.json, state.json). Cloud Hypervisor's --restore is then
// pointed at this tmpdir.
//
// The JSON files are *copied* — not hardlinked — because the restore path
// rewrites config.json in place to swap absolute socket paths for the new
// sandbox. Editing a hardlinked file would corrupt the canonical
// snapshot for every subsequent restore against the same source.
//
// IMPORTANT: the caller is responsible for cleaning up the returned
// tmpdir after CLH has finished restoring (typically deferred until shim
// shutdown). The tmpdir is created as a sibling of srcDir so it lives
// on the same filesystem.
func decompressSnapshotForRestore(srcDir string) (string, error) {
	tmpDir, err := os.MkdirTemp(filepath.Dir(srcDir), filepath.Base(srcDir)+".decomp-")
	if err != nil {
		return "", fmt.Errorf("create decompress tmpdir: %w", err)
	}
	// Best-effort cleanup if anything below fails.
	cleanup := func() { _ = os.RemoveAll(tmpDir) }

	entries, err := os.ReadDir(srcDir)
	if err != nil {
		cleanup()
		return "", fmt.Errorf("read snapshot dir: %w", err)
	}

	var decompressErrs []error
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		srcPath := filepath.Join(srcDir, name)

		switch {
		case strings.HasPrefix(name, snapshotMemoryRangePrefix) &&
			strings.HasSuffix(name, snapshotCompressedSuffix):
			// memory-ranges-N.zst -> memory-ranges-N (decompressed)
			outName := strings.TrimSuffix(name, snapshotCompressedSuffix)
			dstPath := filepath.Join(tmpDir, outName)
			if err := decompressFile(srcPath, dstPath); err != nil {
				decompressErrs = append(decompressErrs, fmt.Errorf("decompress %s: %w", name, err))
			}
		case strings.HasPrefix(name, snapshotMemoryRangePrefix):
			// Mixed snapshot (some compressed, some raw): hardlink the
			// raw blob — it's read-only on the restore path so sharing
			// the inode is safe.
			if err := linkOrCopy(srcPath, filepath.Join(tmpDir, name)); err != nil {
				decompressErrs = append(decompressErrs, err)
			}
		default:
			// JSON / metadata files: COPY (not hardlink) so the
			// rewriteSnapshotConfigForNewSandbox edit is local to this
			// restore and does not corrupt the canonical snapshot.
			if err := copyFile(srcPath, filepath.Join(tmpDir, name)); err != nil {
				decompressErrs = append(decompressErrs, err)
			}
		}
	}
	if len(decompressErrs) > 0 {
		cleanup()
		return "", errors.Join(decompressErrs...)
	}
	return tmpDir, nil
}

// decompressFile streams a zstd-compressed src to a raw dst.
func decompressFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	dec, err := zstd.NewReader(in)
	if err != nil {
		return err
	}
	defer dec.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, dec); err != nil {
		return err
	}
	return out.Sync()
}

// linkOrCopy makes dst a hardlink of src; if hardlinking fails (cross-FS
// or unsupported), falls back to a byte copy.
func linkOrCopy(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	return copyFile(src, dst)
}

// copyFile creates dst as a fresh byte copy of src and fsyncs it. Used for
// snapshot files that the restore path mutates (so that hardlink-shared
// inodes don't corrupt the canonical snapshot).
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
