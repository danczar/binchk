package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/danczar/binchk/internal/analyze"
	"github.com/danczar/binchk/internal/bundleid"
	"github.com/danczar/binchk/internal/config"
	"github.com/danczar/binchk/internal/container"
	"github.com/danczar/binchk/internal/detect"
	"github.com/danczar/binchk/internal/findertag"
	"github.com/danczar/binchk/internal/index"
)

// Recorder publishes an analysis outside its report: the index entry, card,
// path pointers and content map the Quick Look extension reads, and the
// Finder tag. Both the watcher pipeline and `binchk scan` use it.
type Recorder struct {
	Index   *index.Index // nil: do not index
	Config  *config.Config
	Allow   *analyze.HashList
	Version string
	NoTags  bool // never touch Finder tags
}

// Record condenses r (the analysis of path, whose full report is at
// reportPath) and publishes it. st is path's identity state (see
// IdentityState) taken before analysis; nil skips the path pointers. The
// returned entry is never nil, even when publishing fails.
func (rc *Recorder) Record(r *analyze.Report, path, reportPath string, st *index.State) (*index.Entry, error) {
	_, safe := rc.Allow.Lookup(r.TrustKey())
	e := index.NewEntry(r, path, reportPath, rc.Version, safe)
	var errs []error
	if rc.Index != nil && index.IsDigest(e.EntryID) {
		paths := pointerPaths(path)
		if old, err := rc.Index.Get(e.EntryID); err == nil {
			for _, p := range old.Paths {
				if !slices.Contains(paths, p) {
					paths = append(paths, p)
				}
			}
		}
		e.Paths = paths
		var extra index.Extra
		extra.Arches, extra.Size = r.Arches, r.Size
		if err := rc.Index.Put(e, extra); err != nil {
			errs = append(errs, err)
		} else {
			if st != nil && st.Kind == e.Kind {
				for _, p := range pointerPaths(path) {
					if err := rc.Index.Point(p, e, st); err != nil {
						errs = append(errs, err)
					}
				}
			}
			if err := rc.Index.SetContent(e); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := rc.tag(path, e.Verdict, safe); err != nil {
		errs = append(errs, err)
	}
	return e, errors.Join(errs...)
}

// pointerPaths is path, plus the same item reached through its folder's
// real path when that differs (e.g. /tmp vs /private/tmp on macOS), and
// under its name as the folder lists it when that is spelled differently
// (APFS matches names regardless of Unicode normalization, so a shell may
// hand binchk an NFC name for a file stored as NFD), since a reader may see
// any of these spellings.
func pointerPaths(path string) []string {
	dirs := []string{filepath.Dir(path)}
	if dir, err := filepath.EvalSymlinks(dirs[0]); err == nil && dir != dirs[0] {
		dirs = append(dirs, dir)
	}
	names := append([]string{filepath.Base(path)}, listedNames(path)...)
	var out []string
	for _, d := range dirs {
		for _, n := range names {
			if p := filepath.Join(d, n); !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out
}

// listedNames returns the names, other than path's own, under which path's
// folder lists the item at path: only for non-ASCII names (normalization
// is the only way two spellings name one item there) and only for an item
// that has no other hard link, so another name for the same file is never
// taken for a spelling of this one.
func listedNames(path string) []string {
	dir, base := filepath.Split(path)
	if isASCII(base) {
		return nil
	}
	st, err := os.Lstat(path)
	if err != nil || (!st.IsDir() && linkCount(st) != 1) {
		return nil
	}
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, de := range des {
		name := de.Name()
		if name == base || isASCII(name) {
			continue
		}
		if ost, err := os.Lstat(filepath.Join(dir, name)); err == nil && os.SameFile(st, ost) {
			out = append(out, name)
		}
	}
	return out
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// tag applies the Finder tag policy: verdicts in tag_verdicts get binchk's
// tag, everything else (and anything marked safe) loses it.
func (rc *Recorder) tag(path, verdict string, safe bool) error {
	if rc.NoTags || !rc.Config.FinderTags || !findertag.Supported() {
		return nil
	}
	if !safe && rc.Config.Tags(verdict) {
		return findertag.Set(path, verdict)
	}
	return findertag.Clear(path)
}

// untag removes binchk's tag (it only ever touches binchk's own tag).
func (rc *Recorder) untag(path string) error {
	if rc.NoTags || !findertag.Supported() {
		return nil
	}
	return findertag.Clear(path)
}

// holds reports whether path still holds exactly e's content, by hashing
// it: a path pointer's staleness data and a bundle's fingerprint are
// metadata, not enough to take a tag off.
func (rc *Recorder) holds(path string, e *index.Entry) bool {
	if !index.IsDigest(e.TrustKey) {
		return false
	}
	key, kind, err := TrustKey(path)
	return err == nil && kind == e.Kind && key == e.TrustKey
}

// IdentityState returns what a path pointer records about path: a file's
// size and mtime, or an app bundle's tree summary and its main
// executable's size and mtime.
func IdentityState(path string) (*index.State, error) {
	if !detect.IsAppBundle(path) {
		st, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() {
			return nil, errors.New("not a regular file")
		}
		return &index.State{Kind: index.KindFile, Size: st.Size(), MtimeUnixNs: st.ModTime().UnixNano()}, nil
	}
	exe, ok := container.MainExecutable(path)
	if !ok {
		return nil, errors.New("app bundle has no valid main executable")
	}
	est, err := os.Stat(exe)
	if err != nil {
		return nil, err
	}
	root, err := bundleid.Root(path)
	if err != nil {
		return nil, err
	}
	return &index.State{Kind: index.KindBundle, Tree: bundleid.Summarize(root),
		ExecSize: est.Size(), ExecMtimeNs: est.ModTime().UnixNano()}, nil
}

// ContentKey computes path's content key and kind as binchk indexes it:
// a file's SHA-256, or an app bundle's fingerprint.
func ContentKey(path string) (key, kind string, err error) {
	if !detect.IsAppBundle(path) {
		key, err = sha256File(path)
		return key, index.KindFile, err
	}
	exe, ok := container.MainExecutable(path)
	if !ok {
		return "", index.KindBundle, errors.New("app bundle has no valid main executable")
	}
	sum, err := sha256File(exe)
	if err != nil {
		return "", index.KindBundle, err
	}
	key, err = bundleid.Fingerprint(path, sum)
	return key, index.KindBundle, err
}

// TrustKey computes path's trust key and kind as the allowlist uses it: a
// file's SHA-256, or an app bundle's contents digest (which reads every
// file in it).
func TrustKey(path string) (key, kind string, err error) {
	if !detect.IsAppBundle(path) {
		key, err = sha256File(path)
		return key, index.KindFile, err
	}
	exe, ok := container.MainExecutable(path)
	if !ok {
		return "", index.KindBundle, errors.New("app bundle has no valid main executable")
	}
	key, _, err = bundleid.Contents(context.Background(), path, filepath.Base(exe))
	return key, index.KindBundle, err
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
