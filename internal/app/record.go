package app

import (
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
	_, safe := rc.Allow.Lookup(r.ContentKey())
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
// real path when that differs (e.g. /tmp vs /private/tmp on macOS), since
// a reader may see either spelling.
func pointerPaths(path string) []string {
	out := []string{path}
	if dir, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
		if alt := filepath.Join(dir, filepath.Base(path)); alt != path {
			out = append(out, alt)
		}
	}
	return out
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

// holds reports whether path still holds e's content: through a fresh
// pointer to e, or else by computing its content key.
func (rc *Recorder) holds(path string, e *index.Entry) bool {
	st, err := IdentityState(path)
	if err != nil || st.Kind != e.Kind {
		return false
	}
	if p, err := rc.Index.Pointer(path); err == nil && p.Entry == e.EntryID && p.Matches(st) {
		return true
	}
	key, kind, err := ContentKey(path)
	return err == nil && kind == e.Kind && key == e.ContentKey
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
