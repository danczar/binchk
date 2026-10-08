package legacy

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// The helpers below build a vault exactly the way binchk v0.1.1's
// quarantine package did (internal/quarantine at 9de1592): the item is
// renamed into <vault>/<id>.quarantined (bundles into
// <vault>/<id>.quarantined/<Name>), files are made read-only, execute bits
// inside bundles are stripped with the original modes recorded, and the
// record is saved as <vault>/<id>.json.

type v011Entry struct {
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
}

var seq int

func v011ID() string {
	seq++
	return fmt.Sprintf("%s-%08x", time.Now().Format("20060102-150405"), seq)
}

func v011Save(t *testing.T, vault string, e *v011Entry) {
	t.Helper()
	b, _ := json.MarshalIndent(e, "", "  ")
	if err := os.WriteFile(filepath.Join(vault, e.ID+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func v011Vault(t *testing.T, data string) string {
	t.Helper()
	vault := VaultDir(data)
	if err := os.MkdirAll(vault, 0o700); err != nil {
		t.Fatal(err)
	}
	return vault
}

// v011Isolate quarantines a regular file.
func v011Isolate(t *testing.T, vault, path string, at time.Time) *v011Entry {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	id := v011ID()
	e := &v011Entry{
		ID: id, Name: filepath.Base(path), OriginalPath: path, Mode: st.Mode().Perm(), Size: st.Size(),
		StoredPath: filepath.Join(vault, id+".quarantined"), QuarantinedAt: at, Status: "quarantined",
		SHA256: "ab", Verdict: "Suspicious", Score: 30, Summary: "1 high",
	}
	if err := os.Rename(path, e.StoredPath); err != nil {
		t.Fatal(err)
	}
	os.Chmod(e.StoredPath, 0o400)
	v011Save(t, vault, e)
	return e
}

// v011IsolateDir quarantines an .app bundle.
func v011IsolateDir(t *testing.T, vault, path string, at time.Time) *v011Entry {
	t.Helper()
	st, _ := os.Lstat(path)
	id := v011ID()
	holder := filepath.Join(vault, id+".quarantined")
	os.Mkdir(holder, 0o700)
	e := &v011Entry{
		ID: id, Name: filepath.Base(path), OriginalPath: path, Mode: st.Mode().Perm(), Bundle: true,
		StoredPath: filepath.Join(holder, filepath.Base(path)), QuarantinedAt: at, Status: "quarantined",
		Modes: map[string]fs.FileMode{},
	}
	if err := os.Rename(path, e.StoredPath); err != nil {
		t.Fatal(err)
	}
	filepath.WalkDir(e.StoredPath, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		info, _ := d.Info()
		e.Size += info.Size()
		if m := info.Mode().Perm(); m&0o111 != 0 {
			rel, _ := filepath.Rel(e.StoredPath, p)
			e.Modes[rel] = m
			os.Chmod(p, m&^0o111)
		}
		return nil
	})
	v011Save(t, vault, e)
	return e
}

func makeApp(t *testing.T, path string) {
	t.Helper()
	exe := filepath.Join(path, "Contents/MacOS/Tool")
	os.MkdirAll(filepath.Dir(exe), 0o755)
	os.WriteFile(exe, []byte("bin"), 0o755)
	os.WriteFile(filepath.Join(path, "Contents/Info.plist"), []byte("<plist/>"), 0o644)
	os.WriteFile(filepath.Join(path, "Contents/MacOS/helper.sh"), []byte("#!/bin/sh\n"), 0o750)
	os.Symlink("MacOS/Tool", filepath.Join(path, "Contents/link"))
}

func quiet() Logger { return log.New(io.Discard, "", 0) }

func mode(t *testing.T, p string) fs.FileMode {
	t.Helper()
	st, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func TestMigrateRestoresEverything(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	dl := filepath.Join(root, "Downloads")
	os.MkdirAll(dl, 0o755)
	vault := v011Vault(t, data)
	now := time.Now()

	// A plain file, an app bundle, and a file whose name was taken since.
	tool := filepath.Join(dl, "tool")
	os.WriteFile(tool, []byte("payload"), 0o755)
	v011Isolate(t, vault, tool, now.Add(-3*time.Minute))

	app := filepath.Join(dl, "Tool.app")
	makeApp(t, app)
	v011IsolateDir(t, vault, app, now.Add(-2*time.Minute))

	setup := filepath.Join(dl, "setup.dmg")
	os.WriteFile(setup, []byte("image"), 0o644)
	v011Isolate(t, vault, setup, now.Add(-time.Minute))
	os.WriteFile(setup, []byte("newer download"), 0o644)

	// An item whose original folder is gone.
	gone := filepath.Join(root, "Old", "x.pkg")
	os.MkdirAll(filepath.Dir(gone), 0o755)
	os.WriteFile(gone, []byte("pkg"), 0o644)
	v011Isolate(t, vault, gone, now)
	os.Remove(filepath.Dir(gone))

	restored, err := Migrate(data, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 4 {
		t.Fatalf("restored %d items: %+v", len(restored), restored)
	}
	if b, _ := os.ReadFile(tool); string(b) != "payload" {
		t.Fatalf("tool content %q", b)
	}
	if runtime.GOOS != "windows" {
		if m := mode(t, tool); m != 0o755 {
			t.Errorf("tool mode %v", m)
		}
		if m := mode(t, filepath.Join(app, "Contents/MacOS/Tool")); m != 0o755 {
			t.Errorf("bundle executable mode %v", m)
		}
		if m := mode(t, filepath.Join(app, "Contents/MacOS/helper.sh")); m != 0o750 {
			t.Errorf("bundle script mode %v", m)
		}
		if l, _ := os.Readlink(filepath.Join(app, "Contents/link")); l != "MacOS/Tool" {
			t.Errorf("symlink lost: %q", l)
		}
	}
	if b, _ := os.ReadFile(setup); string(b) != "newer download" {
		t.Fatal("existing file overwritten")
	}
	if b, _ := os.ReadFile(filepath.Join(dl, "setup (restored 1).dmg")); string(b) != "image" {
		t.Fatalf("conflicting item not restored beside it: %q", b)
	}
	if b, _ := os.ReadFile(gone); string(b) != "pkg" {
		t.Fatal("item for a deleted folder not restored")
	}
	if _, err := os.Lstat(vault); !os.IsNotExist(err) {
		t.Fatal("vault not removed")
	}

	// Idempotent.
	again, err := Migrate(data, quiet())
	if err != nil || len(again) != 0 {
		t.Fatalf("second run: %v %v", again, err)
	}
}

// Every way a migration can be interrupted resumes without losing or
// overwriting anything.
func TestMigrateResumes(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	dl := filepath.Join(root, "Downloads")
	os.MkdirAll(dl, 0o755)
	vault := v011Vault(t, data)
	journal := func(e *v011Entry, dst string) {
		b, _ := os.ReadFile(filepath.Join(vault, e.ID+".json"))
		var m map[string]any
		json.Unmarshal(b, &m)
		m["restoring_to"] = dst
		b, _ = json.Marshal(m)
		os.WriteFile(filepath.Join(vault, e.ID+".json"), b, 0o600)
	}

	// 1. Crashed after the move, before the record was removed.
	a := filepath.Join(dl, "a")
	os.WriteFile(a, []byte("A"), 0o755)
	ea := v011Isolate(t, vault, a, time.Now())
	journal(ea, a)
	os.Rename(ea.StoredPath, a)

	// 2. Crashed after journalling, before the move.
	b := filepath.Join(dl, "b")
	os.WriteFile(b, []byte("B"), 0o755)
	eb := v011Isolate(t, vault, b, time.Now())
	journal(eb, b)

	// 3. Journalled destination taken by something else since.
	c := filepath.Join(dl, "c")
	os.WriteFile(c, []byte("C"), 0o755)
	ec := v011Isolate(t, vault, c, time.Now())
	journal(ec, c)
	os.WriteFile(c, []byte("someone else's"), 0o644)

	// 4. Crashed during a cross-volume copy: a partial temporary copy.
	d := filepath.Join(dl, "d.app")
	makeApp(t, d)
	ed := v011IsolateDir(t, vault, d, time.Now())
	journal(ed, d)
	os.MkdirAll(filepath.Join(tempName(dl, ed.ID), "Contents"), 0o755)

	// 5. A record whose item was already gone (deleted by hand).
	e := filepath.Join(dl, "e")
	os.WriteFile(e, []byte("E"), 0o644)
	ee := v011Isolate(t, vault, e, time.Now())
	os.Chmod(ee.StoredPath, 0o600)
	os.Remove(ee.StoredPath)

	restored, err := Migrate(data, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 4 {
		t.Fatalf("restored %+v", restored)
	}
	for p, want := range map[string]string{
		a: "A", b: "B", c: "someone else's", filepath.Join(dl, "c (restored 1)"): "C",
		filepath.Join(d, "Contents/MacOS/Tool"): "bin",
	} {
		if got, err := os.ReadFile(p); err != nil || string(got) != want {
			t.Errorf("%s: %q %v", p, got, err)
		}
	}
	if _, err := os.Lstat(tempName(dl, ed.ID)); !os.IsNotExist(err) {
		t.Error("temporary copy left behind")
	}
	if _, err := os.Lstat(vault); !os.IsNotExist(err) {
		t.Fatal("vault not removed")
	}
}

// What cannot be restored stays put, and is retried next time.
func TestMigrateKeepsWhatItCannotRestore(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	vault := v011Vault(t, data)
	// A stored item without a record (v0.1.1 crashed between move and save).
	os.WriteFile(filepath.Join(vault, "20260101-000000-deadbeef.quarantined"), []byte("orphan"), 0o400)
	// A record with a relative original path.
	bad := &v011Entry{ID: "20260101-000000-cafebabe", Name: "x", OriginalPath: "x", Status: "quarantined",
		StoredPath: filepath.Join(vault, "20260101-000000-cafebabe.quarantined")}
	os.WriteFile(bad.StoredPath, []byte("x"), 0o400)
	v011Save(t, vault, bad)

	restored, err := Migrate(data, quiet())
	if err == nil || len(restored) != 0 {
		t.Fatalf("got %v, %v", restored, err)
	}
	for _, p := range []string{"20260101-000000-deadbeef.quarantined", bad.ID + ".json", bad.ID + ".quarantined"} {
		if _, err := os.Lstat(filepath.Join(vault, p)); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}

func TestMigrateNoVault(t *testing.T) {
	restored, err := Migrate(t.TempDir(), quiet())
	if err != nil || restored != nil {
		t.Fatalf("%v %v", restored, err)
	}
}

func TestCopyTree(t *testing.T) {
	src := t.TempDir()
	os.MkdirAll(filepath.Join(src, "a/b"), 0o755)
	os.WriteFile(filepath.Join(src, "a/b/x"), []byte("hi"), 0o750)
	os.Symlink("b/x", filepath.Join(src, "a/l"))
	dst := filepath.Join(t.TempDir(), "copy")
	if err := copyTree(src, dst); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(dst, "a/b/x")); st == nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o750) {
		t.Errorf("file: %v", st)
	}
	if l, _ := os.Readlink(filepath.Join(dst, "a/l")); l != "b/x" {
		t.Errorf("link %q", l)
	}
}
