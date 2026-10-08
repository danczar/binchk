// Package legacy returns files held in the quarantine vault of binchk
// v0.1.x to where they came from. binchk no longer quarantines anything;
// this runs once at startup, is idempotent, and resumes safely if it was
// interrupted.
//
// The v0.1.x vault (<data>/quarantine) holds, per item:
//
//	<id>.json                 the entry (Entry below)
//	<id>.quarantined          a file, mode 0400
//	<id>.quarantined/<Name>   an .app bundle, execute bits stripped (Entry.Modes)
package legacy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// VaultDir is the v0.1.x vault inside a data directory.
func VaultDir(dataDir string) string { return filepath.Join(dataDir, "quarantine") }

// Entry is the v0.1.x vault record, plus RestoringTo, the journal field this
// migration adds before it moves anything.
type Entry struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	OriginalPath  string                 `json:"original_path"`
	StoredPath    string                 `json:"stored_path"`
	Mode          fs.FileMode            `json:"mode"`
	Size          int64                  `json:"size"`
	QuarantinedAt time.Time              `json:"quarantined_at"`
	Status        string                 `json:"status"`
	Bundle        bool                   `json:"bundle,omitempty"`
	Modes         map[string]fs.FileMode `json:"modes,omitempty"`
	SHA256        string                 `json:"sha256,omitempty"`
	Verdict       string                 `json:"verdict,omitempty"`
	Score         int                    `json:"score,omitempty"`
	Summary       string                 `json:"summary,omitempty"`
	ReportPath    string                 `json:"report_path,omitempty"`
	RestoringTo   string                 `json:"restoring_to,omitempty"`
}

// Restored describes one item put back.
type Restored struct {
	Name   string
	From   string // where it was held in the vault
	To     string // where it is now
	Bundle bool
}

// Logger receives one line per action.
type Logger interface {
	Printf(format string, v ...any)
}

// Migrate restores every item in dataDir's vault to its original path
// (with a " (restored N)" suffix if that name is taken; nothing is ever
// overwritten) and removes the vault once it is empty. Items it cannot
// restore stay in the vault and are reported in the error; a later call
// retries them.
func Migrate(dataDir string, lg Logger) ([]Restored, error) {
	vault := VaultDir(dataDir)
	if _, err := os.Lstat(vault); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	matches, err := filepath.Glob(filepath.Join(vault, "*.json"))
	if err != nil {
		return nil, err
	}
	// Restore oldest first so name clashes resolve in arrival order.
	var entries []*Entry
	var errs []error
	for _, m := range matches {
		e, err := load(vault, m)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].QuarantinedAt.Before(entries[j].QuarantinedAt) })

	var done []Restored
	for _, e := range entries {
		r, err := restore(vault, e, lg)
		if err != nil {
			lg.Printf("legacy: could not restore %s to %s: %v", e.Name, e.OriginalPath, err)
			errs = append(errs, fmt.Errorf("%s: %w", e.Name, err))
			continue
		}
		if r != nil {
			done = append(done, *r)
		}
	}
	// Leftover temporary files from v0.1.x's own atomic saves.
	if tmps, _ := filepath.Glob(filepath.Join(vault, "*.json.tmp")); len(tmps) > 0 {
		for _, t := range tmps {
			os.Remove(t)
		}
	}
	if err := os.Remove(vault); err == nil {
		lg.Printf("legacy: removed the empty quarantine vault %s", vault)
	} else if !errors.Is(err, fs.ErrNotExist) {
		if rest, _ := os.ReadDir(vault); len(rest) > 0 {
			names := make([]string, 0, len(rest))
			for _, d := range rest {
				names = append(names, d.Name())
			}
			lg.Printf("legacy: %s still holds %s; left in place", vault, strings.Join(names, ", "))
		}
	}
	return done, errors.Join(errs...)
}

// load reads and validates one vault record. Stored paths are recomputed
// from the record's ID and name rather than trusted.
func load(vault, jsonPath string) (*Entry, error) {
	b, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, err
	}
	var e Entry
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(jsonPath), err)
	}
	id := strings.TrimSuffix(filepath.Base(jsonPath), ".json")
	switch {
	case e.ID != id || !filepath.IsLocal(id) || strings.ContainsAny(id, `/\`):
		return nil, fmt.Errorf("%s: record ID %q does not match", filepath.Base(jsonPath), e.ID)
	case !filepath.IsAbs(e.OriginalPath):
		return nil, fmt.Errorf("%s: original path %q is not absolute", id, e.OriginalPath)
	case e.Bundle && (e.Name == "" || !filepath.IsLocal(e.Name) || strings.ContainsAny(e.Name, `/\`)):
		return nil, fmt.Errorf("%s: bad bundle name %q", id, e.Name)
	}
	e.OriginalPath = filepath.Clean(e.OriginalPath)
	e.StoredPath = filepath.Join(vault, id+".quarantined")
	if e.Bundle {
		e.StoredPath = filepath.Join(e.StoredPath, e.Name)
	}
	return &e, nil
}

func save(vault string, e *Entry) error {
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	p := filepath.Join(vault, e.ID+".json")
	if err := os.WriteFile(p+".tmp", b, 0o600); err != nil {
		return err
	}
	if err := syncFile(p + ".tmp"); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// freeName returns path, or "<base> (restored N)<ext>" for the first N
// that is not taken.
func freeName(path string) string {
	if !exists(path) {
		return path
	}
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	for i := 1; ; i++ {
		p := fmt.Sprintf("%s (restored %d)%s", base, i, ext)
		if !exists(p) {
			return p
		}
	}
}

// restore puts one item back. The destination is journalled in the record
// before anything moves, so an interrupted run knows on resume whether the
// item already reached it:
//
//   - stored item gone, destination present: the move finished; tidy up.
//   - stored item present: (re)do the move. If the journalled destination
//     exists by then, it is not ours to overwrite, so a fresh name is used.
//   - both gone: nothing is left to restore; the record is dropped.
func restore(vault string, e *Entry, lg Logger) (*Restored, error) {
	holder := filepath.Join(vault, e.ID+".quarantined")
	stored := exists(e.StoredPath)
	if !stored {
		if e.RestoringTo != "" && exists(e.RestoringTo) {
			finish(e, e.RestoringTo)
			lg.Printf("legacy: restored %s -> %s (completing an interrupted migration)", e.Name, e.RestoringTo)
			return &Restored{Name: e.Name, From: e.StoredPath, To: e.RestoringTo, Bundle: e.Bundle}, cleanup(vault, e, holder)
		}
		lg.Printf("legacy: %s is no longer in the vault; dropping its record", e.Name)
		return nil, cleanup(vault, e, holder)
	}
	// Leftovers of an interrupted cross-volume copy are ours to remove.
	removeTemps(filepath.Dir(e.OriginalPath), e.ID)

	dst := e.RestoringTo
	if dst == "" || exists(dst) {
		dst = freeName(e.OriginalPath)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return nil, err
	}
	e.RestoringTo = dst
	if err := save(vault, e); err != nil {
		return nil, err
	}
	if err := move(e.StoredPath, dst, e.ID); err != nil {
		return nil, err
	}
	finish(e, dst)
	lg.Printf("legacy: restored %s -> %s", e.Name, dst)
	return &Restored{Name: e.Name, From: e.StoredPath, To: dst, Bundle: e.Bundle}, cleanup(vault, e, holder)
}

// finish gives the restored item back its recorded permissions.
func finish(e *Entry, dst string) {
	if !e.Bundle {
		if st, err := os.Lstat(dst); err == nil && st.Mode().IsRegular() && e.Mode.Perm() != 0 {
			_ = os.Chmod(dst, e.Mode.Perm())
		}
		return
	}
	for rel, m := range e.Modes {
		if !filepath.IsLocal(rel) {
			continue
		}
		p := filepath.Join(dst, rel)
		if st, err := os.Lstat(p); err == nil && st.Mode().IsRegular() {
			_ = os.Chmod(p, m.Perm())
		}
	}
}

func cleanup(vault string, e *Entry, holder string) error {
	if e.Bundle {
		os.Remove(holder) // only once empty
	}
	err := os.Remove(filepath.Join(vault, e.ID+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	return err
}

// tempName is where a cross-volume copy is assembled before its rename.
func tempName(dir, id string) string { return filepath.Join(dir, ".binchk-restore-"+id) }

func removeTemps(dir, id string) {
	t := tempName(dir, id)
	if st, err := os.Lstat(t); err == nil {
		if st.IsDir() {
			makeRemovable(t)
		}
		os.RemoveAll(t)
	}
}

// move renames src to dst, or across volumes copies it to a temporary name
// next to dst, renames that into place and only then removes src. At no
// point is the item absent from both places.
func move(src, dst, id string) error {
	if exists(dst) {
		return fmt.Errorf("%s already exists", dst)
	}
	// The vault stored files read-only; the move needs no write access, but
	// a cross-volume copy has to read it.
	if st, err := os.Lstat(src); err == nil && st.Mode().IsRegular() {
		_ = os.Chmod(src, 0o600)
	}
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	tmp := tempName(filepath.Dir(dst), id)
	st, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if st.IsDir() {
		err = copyTree(src, tmp)
	} else {
		err = copyFile(src, tmp, 0o600)
	}
	if err == nil {
		err = os.Rename(tmp, dst)
	}
	if err != nil {
		removeTemps(filepath.Dir(dst), id)
		return err
	}
	if st.IsDir() {
		makeRemovable(src)
	}
	return os.RemoveAll(src)
}

// makeRemovable gives every directory in a tree owner write permission, so
// bundles with read-only directories can be deleted.
func makeRemovable(root string) {
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			os.Chmod(p, 0o700)
		}
		return nil
	})
}

func syncFile(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func copyFile(src, dst string, mode fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// copyTree copies a directory preserving modes and symlinks (frameworks in
// app bundles depend on them).
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(target, info.Mode().Perm()|0o700)
		case d.Type()&fs.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case d.Type().IsRegular():
			return copyFile(p, target, info.Mode().Perm())
		}
		return nil
	})
}
