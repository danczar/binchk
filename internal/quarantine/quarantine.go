// Package quarantine isolates suspect files in a private vault: moved out of
// the user's folders, renamed so nothing will launch them by extension, and
// stripped of execute permission.
package quarantine

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Status string

const (
	Quarantined Status = "quarantined"
	Restored    Status = "restored"
	Deleted     Status = "deleted"
)

type Entry struct {
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	OriginalPath  string      `json:"original_path"`
	StoredPath    string      `json:"stored_path"`
	Mode          fs.FileMode `json:"mode"`
	Size          int64       `json:"size"`
	QuarantinedAt time.Time   `json:"quarantined_at"`
	Status        Status      `json:"status"`
	// Bundle entries are directories (macOS .app). Modes records the
	// original permissions of files whose execute bits were stripped.
	Bundle bool                   `json:"bundle,omitempty"`
	Modes  map[string]fs.FileMode `json:"modes,omitempty"`
	// Filled in after analysis.
	SHA256     string `json:"sha256,omitempty"`
	Verdict    string `json:"verdict,omitempty"`
	Score      int    `json:"score,omitempty"`
	Summary    string `json:"summary,omitempty"`
	ReportPath string `json:"report_path,omitempty"`
}

type Store struct {
	dir string
	mu  sync.Mutex
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(dir, 0o700)
	return &Store{dir: dir}, nil
}

func (s *Store) Dir() string { return s.dir }

func newID() string {
	var b [4]byte
	rand.Read(b[:])
	return time.Now().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}

// Isolate moves path into the vault. Rename is atomic and instant on the
// same volume; across volumes we copy then remove.
func (s *Store) Isolate(path string) (*Entry, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return s.isolateDir(path, st)
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	id := newID()
	e := &Entry{
		ID: id, Name: filepath.Base(path), OriginalPath: path, Mode: st.Mode().Perm(), Size: st.Size(),
		StoredPath: filepath.Join(s.dir, id+".quarantined"), QuarantinedAt: time.Now(), Status: Quarantined,
	}
	if err := move(path, e.StoredPath); err != nil {
		return nil, err
	}
	_ = os.Chmod(e.StoredPath, 0o400)
	return e, s.Save(e)
}

// isolateDir quarantines a bundle directory. It is stored as
// <id>.quarantined/<Name>.app — the bundle keeps its name so Apple's tools
// still recognise it — and every execute bit inside is removed (the original
// modes are recorded so Restore puts them back exactly).
func (s *Store) isolateDir(path string, st fs.FileInfo) (*Entry, error) {
	id := newID()
	holder := filepath.Join(s.dir, id+".quarantined")
	if err := os.Mkdir(holder, 0o700); err != nil {
		return nil, err
	}
	e := &Entry{
		ID: id, Name: filepath.Base(path), OriginalPath: path, Mode: st.Mode().Perm(), Bundle: true,
		StoredPath: filepath.Join(holder, filepath.Base(path)), QuarantinedAt: time.Now(), Status: Quarantined,
		Modes: map[string]fs.FileMode{},
	}
	if err := move(path, e.StoredPath); err != nil {
		os.Remove(holder)
		return nil, err
	}
	filepath.WalkDir(e.StoredPath, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		e.Size += info.Size()
		if m := info.Mode().Perm(); m&0o111 != 0 {
			rel, _ := filepath.Rel(e.StoredPath, p)
			e.Modes[rel] = m
			_ = os.Chmod(p, m&^0o111)
		}
		return nil
	})
	return e, s.Save(e)
}

func (s *Store) Save(e *Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	p := filepath.Join(s.dir, e.ID+".json")
	if err := os.WriteFile(p+".tmp", b, 0o600); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}

// Restore moves the file back, never overwriting something that has since
// appeared at the original path. It returns the path it restored to.
func (s *Store) Restore(e *Entry) (string, error) {
	dst := e.OriginalPath
	if _, err := os.Lstat(dst); err == nil {
		ext := filepath.Ext(dst)
		base := strings.TrimSuffix(dst, ext)
		for i := 1; ; i++ {
			dst = fmt.Sprintf("%s (restored %d)%s", base, i, ext)
			if _, err := os.Lstat(dst); errors.Is(err, fs.ErrNotExist) {
				break
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	if e.Bundle {
		for rel, m := range e.Modes {
			_ = os.Chmod(filepath.Join(e.StoredPath, rel), m)
		}
		if err := move(e.StoredPath, dst); err != nil {
			return "", err
		}
		os.Remove(filepath.Dir(e.StoredPath))
		e.Status = Restored
		return dst, s.remove(e)
	}
	_ = os.Chmod(e.StoredPath, 0o600)
	if err := move(e.StoredPath, dst); err != nil {
		_ = os.Chmod(e.StoredPath, 0o400)
		return "", err
	}
	_ = os.Chmod(dst, e.Mode)
	e.Status = Restored
	return dst, s.remove(e)
}

// Delete permanently removes the quarantined file.
func (s *Store) Delete(e *Entry) error {
	if e.Bundle {
		holder := filepath.Dir(e.StoredPath)
		// Bundles may contain read-only directories; make them removable.
		filepath.WalkDir(holder, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				os.Chmod(p, 0o700)
			}
			return nil
		})
		if err := os.RemoveAll(holder); err != nil {
			return err
		}
		e.Status = Deleted
		return s.remove(e)
	}
	_ = os.Chmod(e.StoredPath, 0o600)
	if err := os.Remove(e.StoredPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	e.Status = Deleted
	return s.remove(e)
}

func (s *Store) remove(e *Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(filepath.Join(s.dir, e.ID+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// List returns quarantined entries, newest first.
func (s *Store) List() ([]*Entry, error) {
	matches, err := filepath.Glob(filepath.Join(s.dir, "*.json"))
	if err != nil {
		return nil, err
	}
	var out []*Entry
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		var e Entry
		if json.Unmarshal(b, &e) != nil || e.Status != Quarantined {
			continue
		}
		if _, err := os.Stat(e.StoredPath); err != nil {
			continue
		}
		out = append(out, &e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].QuarantinedAt.After(out[j].QuarantinedAt) })
	return out, nil
}

func move(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if st, err := os.Lstat(src); err == nil && st.IsDir() {
		if err := copyTree(src, dst); err != nil {
			os.RemoveAll(dst)
			return err
		}
		return os.RemoveAll(src)
	}
	// Cross-device: copy, fsync, then remove the source.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return err
	}
	in.Close()
	if err := os.Remove(src); err != nil {
		os.Remove(dst)
		return err
	}
	return nil
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
			in, err := os.Open(p)
			if err != nil {
				return err
			}
			defer in.Close()
			out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, in); err != nil {
				out.Close()
				return err
			}
			return out.Close()
		}
		return nil
	})
}
