package quarantine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBundleRoundTrip(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "Downloads", "Foo.app")
	exe := filepath.Join(app, "Contents/MacOS/Foo")
	os.MkdirAll(filepath.Dir(exe), 0o755)
	os.WriteFile(exe, []byte("bin"), 0o755)
	os.WriteFile(filepath.Join(app, "Contents/Info.plist"), []byte("<plist/>"), 0o644)
	os.Symlink("MacOS/Foo", filepath.Join(app, "Contents/link"))

	s, err := Open(filepath.Join(root, "vault"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.Isolate(app)
	if err != nil {
		t.Fatal(err)
	}
	if !e.Bundle || filepath.Base(e.StoredPath) != "Foo.app" {
		t.Fatalf("entry %+v", e)
	}
	if _, err := os.Stat(app); !os.IsNotExist(err) {
		t.Fatal("bundle still at original path")
	}
	st, _ := os.Stat(filepath.Join(e.StoredPath, "Contents/MacOS/Foo"))
	if st.Mode().Perm()&0o111 != 0 {
		t.Errorf("exec bit kept in quarantine: %v", st.Mode())
	}
	if l, err := s.List(); err != nil || len(l) != 1 {
		t.Fatalf("list: %v %v", l, err)
	}
	dst, err := s.Restore(e)
	if err != nil || dst != app {
		t.Fatalf("restore: %s %v", dst, err)
	}
	st, _ = os.Stat(exe)
	if st.Mode().Perm() != 0o755 {
		t.Errorf("mode not restored: %v", st.Mode())
	}
	if l, _ := os.Readlink(filepath.Join(app, "Contents/link")); l != "MacOS/Foo" {
		t.Errorf("symlink lost: %q", l)
	}

	// isolate again, then delete (with a read-only directory inside)
	e, _ = s.Isolate(app)
	os.Chmod(filepath.Join(e.StoredPath, "Contents/MacOS"), 0o555)
	if err := s.Delete(e); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(e.StoredPath)); !os.IsNotExist(err) {
		t.Error("bundle not deleted")
	}
}

func TestCopyTreeCrossDevice(t *testing.T) {
	src := t.TempDir()
	os.MkdirAll(filepath.Join(src, "a/b"), 0o755)
	os.WriteFile(filepath.Join(src, "a/b/x"), []byte("hi"), 0o750)
	os.Symlink("b/x", filepath.Join(src, "a/l"))
	dst := filepath.Join(t.TempDir(), "copy")
	if err := copyTree(src, dst); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(dst, "a/b/x")); st == nil || st.Mode().Perm() != 0o750 {
		t.Errorf("file: %v", st)
	}
	if l, _ := os.Readlink(filepath.Join(dst, "a/l")); l != "b/x" {
		t.Errorf("link %q", l)
	}
}
