package app

import (
	"errors"
	"io/fs"
	"path/filepath"

	"github.com/danczar/binchk/internal/analyze"
	"github.com/danczar/binchk/internal/config"
	"github.com/danczar/binchk/internal/findertag"
	"github.com/danczar/binchk/internal/index"
)

// Recorder publishes an analysis outside its report: the index entry, card
// and path pointer the Quick Look extension reads, and the Finder tag. Both
// the watcher pipeline and `binchk scan` use it.
type Recorder struct {
	Index   *index.Index // nil: do not index
	Config  *config.Config
	Allow   *analyze.HashList
	Version string
	NoTags  bool // never touch Finder tags
}

// Record condenses r (the analysis of path, whose full report is at
// reportPath) and publishes it. idSt is the state of path's identity file
// (see IdentityStat) taken before analysis; nil skips the path pointer. The
// returned entry is never nil, even when publishing fails.
func (rc *Recorder) Record(r *analyze.Report, path, reportPath string, idSt fs.FileInfo) (*index.Entry, error) {
	_, safe := rc.Allow.Lookup(r.Hashes.SHA256)
	e := index.NewEntry(r, path, reportPath, rc.Version, safe)
	var errs []error
	if rc.Index != nil && index.IsDigest(e.SHA256) {
		var extra index.Extra
		extra.Arches, extra.Size = r.Arches, r.Size
		if err := rc.Index.Put(e, extra); err != nil {
			errs = append(errs, err)
		} else if idSt != nil {
			for _, p := range pointerPaths(path) {
				if err := rc.Index.Point(p, e.SHA256, idSt); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	if err := rc.tag(path, e.Verdict, safe); err != nil {
		errs = append(errs, err)
	}
	return e, errors.Join(errs...)
}

// pointerPaths is path, plus the same file reached through its folder's
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
