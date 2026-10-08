// Package bundleid identifies a macOS application bundle by what it holds.
//
// A bundle is a directory, so it has no single file hash. Its content key
// is the bundle fingerprint: the SHA-256 of a canonical encoding of
//
//   - the main executable's SHA-256,
//   - the SHA-256 of Contents/_CodeSignature/CodeResources (or a fixed
//     marker when that is not a regular file), and
//   - a manifest of every entry under the bundle, sorted by relative path,
//     walked without following symbolic links: (path, type, size for files,
//     target for symbolic links).
//
// The Quick Look extension (macos/QuickLook, BinchkIndex.swift) implements
// the same algorithm; both sides test it against the same vector. Any
// change here must be made there too.
//
// The fingerprint records file sizes, not contents, so that a reader can
// compute it from metadata and two files only. It tells items apart in the
// report index, but it does not vouch for every byte: a copy with a nested
// file swapped for another of the same size has the same fingerprint.
// Trust therefore uses the bundle contents digest (Contents), the same
// encoding with each file's SHA-256 in place of its size. Only binchk
// computes it (it reads every file); the allowlist and Mark as safe key
// bundles by it.
package bundleid

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Domain separates fingerprints from every other SHA-256 binchk computes.
const Domain = "binchk bundle fingerprint v2"

// ContentsDomain separates contents digests from fingerprints.
const ContentsDomain = "binchk bundle contents v2"

// NoCodeResources stands in for the seal's hash when a bundle has no
// regular Contents/_CodeSignature/CodeResources file.
const NoCodeResources = "none"

// ValidExecutableName reports whether a CFBundleExecutable value names a
// file directly inside Contents/MacOS. Anything else (empty, ".", "..", a
// path, a NUL) leaves the bundle without a main executable.
func ValidExecutableName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00")
}

// Tree summarises a directory tree: entries (the root included), the sum
// of their lstat sizes and the newest lstat mtime. A tree with the same
// summary is taken to be unchanged.
type Tree struct {
	Entries     int64
	Size        int64
	MtimeUnixNs int64
}

// Summarize walks dir without following symbolic links (dir itself is
// taken as given).
func Summarize(dir string) Tree {
	t, _ := SummarizeLimit(dir, 0)
	return t
}

// SummarizeLimit is Summarize that stops after limit entries (0: no
// limit), and reports whether it saw the whole tree.
func SummarizeLimit(dir string, limit int64) (Tree, bool) {
	var t Tree
	complete := true
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if limit > 0 && t.Entries >= limit {
			complete = false
			return filepath.SkipAll
		}
		if err != nil {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		t.Entries++
		t.Size += info.Size()
		t.MtimeUnixNs = max(t.MtimeUnixNs, info.ModTime().UnixNano())
		return nil
	})
	return t, complete
}

// Root resolves a bundle path to the directory that is walked: symbolic
// links in the path (including a link to the bundle itself) are followed.
func Root(bundle string) (string, error) {
	root, err := filepath.EvalSymlinks(bundle)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(root)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", errors.New("bundleid: not a directory")
	}
	return root, nil
}

// Entry is one manifest line.
type Entry struct {
	Path  string // relative, '/'-separated
	Type  byte   // 'f' file, 'd' directory, 'l' symbolic link, 'o' other
	Value string // size for files, target for links, "" otherwise
}

// Manifest lists every entry under root (root excluded), sorted bytewise
// by path. Any entry that cannot be read fails the whole manifest.
func Manifest(root string) ([]Entry, error) {
	var out []Entry
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		e := Entry{Path: filepath.ToSlash(rel)}
		switch t := d.Type(); {
		case t.IsDir():
			e.Type = 'd'
		case t&fs.ModeSymlink != 0:
			e.Type = 'l'
			if e.Value, err = os.Readlink(p); err != nil {
				return err
			}
		case t.IsRegular():
			info, err := d.Info()
			if err != nil {
				return err
			}
			e.Type, e.Value = 'f', strconv.FormatInt(info.Size(), 10)
		default:
			e.Type = 'o'
		}
		out = append(out, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// Fingerprint computes the bundle fingerprint of bundle, whose main
// executable has SHA-256 mainSHA256 (lowercase hex).
func Fingerprint(bundle, mainSHA256 string) (string, error) {
	if len(mainSHA256) != 64 {
		return "", errors.New("bundleid: no main executable hash")
	}
	root, err := Root(bundle)
	if err != nil {
		return "", err
	}
	seal, err := codeResources(root)
	if err != nil {
		return "", err
	}
	m, err := Manifest(root)
	if err != nil {
		return "", err
	}
	return Encode(strings.ToLower(mainSHA256), seal, m), nil
}

// Contents computes the bundle contents digest of bundle, whose main
// executable is Contents/MacOS/exe: the fingerprint's encoding under
// ContentsDomain, with the SHA-256 of every regular file as its manifest
// value (the seal's and the main executable's included). It reads every
// file in the bundle, without following symbolic links, and also returns
// the main executable's SHA-256 so a caller can check that it hashed the
// same main executable as the analysis did.
func Contents(ctx context.Context, bundle, exe string) (digest, mainSHA256 string, err error) {
	if !ValidExecutableName(exe) {
		return "", "", errors.New("bundleid: invalid main executable name")
	}
	root, err := Root(bundle)
	if err != nil {
		return "", "", err
	}
	m, err := Manifest(root)
	if err != nil {
		return "", "", err
	}
	seal := NoCodeResources
	mainRel := "Contents/MacOS/" + exe
	for i := range m {
		e := &m[i]
		if e.Type != 'f' {
			continue
		}
		sum, err := hashRegular(ctx, filepath.Join(root, filepath.FromSlash(e.Path)))
		if err != nil {
			return "", "", err
		}
		e.Value = sum
		switch e.Path {
		case mainRel:
			mainSHA256 = sum
		case "Contents/_CodeSignature/CodeResources":
			seal = sum
		}
	}
	if mainSHA256 == "" {
		return "", "", errors.New("bundleid: no main executable")
	}
	return encode(ContentsDomain, mainSHA256, seal, m), mainSHA256, nil
}

// hashRegular hashes the regular file at p, refusing one that is replaced
// (e.g. by a symbolic link) between the check and the read.
func hashRegular(ctx context.Context, p string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	st, err := os.Lstat(p)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", errors.New("bundleid: " + p + " is no longer a regular file")
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if fst, err := f.Stat(); err != nil || !os.SameFile(st, fst) {
		return "", errors.New("bundleid: " + p + " changed while reading")
	}
	h := sha256.New()
	buf := make([]byte, 1<<20)
	for {
		n, err := f.Read(buf)
		h.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Encode is the canonical, length-prefixed encoding, hashed:
//
//	str(Domain) str(main) str(seal) u64(len(m)) { str(path) str(type) str(value) }
//
// where str(s) is u64(len(s)) followed by s, and u64 is big-endian.
func Encode(mainSHA256, seal string, m []Entry) string {
	return encode(Domain, mainSHA256, seal, m)
}

func encode(domain, mainSHA256, seal string, m []Entry) string {
	h := sha256.New()
	str := func(s string) {
		u64(h, uint64(len(s)))
		io.WriteString(h, s)
	}
	str(domain)
	str(mainSHA256)
	str(seal)
	u64(h, uint64(len(m)))
	for _, e := range m {
		str(e.Path)
		str(string(e.Type))
		str(e.Value)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func u64(h hash.Hash, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	h.Write(b[:])
}

// codeResources hashes the bundle's seal file without following a
// symbolic link to it.
func codeResources(root string) (string, error) {
	p := filepath.Join(root, "Contents", "_CodeSignature", "CodeResources")
	st, err := os.Lstat(p)
	if err != nil || !st.Mode().IsRegular() {
		return NoCodeResources, nil
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if fst, err := f.Stat(); err != nil || !os.SameFile(st, fst) {
		return "", errors.New("bundleid: CodeResources changed while reading")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
