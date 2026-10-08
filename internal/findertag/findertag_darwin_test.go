package findertag

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/danczar/binchk/internal/bplist"
)

func writeTags(t *testing.T, path string, tags ...string) {
	t.Helper()
	if err := unix.Setxattr(path, attrName, bplist.EncodeStrings(tags), 0); err != nil {
		t.Fatal(err)
	}
}

func mustGet(t *testing.T, path string) []string {
	t.Helper()
	tags, err := Get(path)
	if err != nil {
		t.Fatal(err)
	}
	return tags
}

func TestSetKeepsUserTags(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tool.dmg")
	os.WriteFile(p, []byte("x"), 0o644)
	st0, _ := os.Stat(p)
	writeTags(t, p, "Work", "Red\n6", "Projekt Ü\n4")

	if err := Set(p, "Suspicious"); err != nil {
		t.Fatal(err)
	}
	if got, want := mustGet(t, p), []string{"Work", "Red\n6", "Projekt Ü\n4", "binchk: Suspicious\n7"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after Suspicious: %q", got)
	}
	if err := Set(p, "Malicious"); err != nil {
		t.Fatal(err)
	}
	if got, want := mustGet(t, p), []string{"Work", "Red\n6", "Projekt Ü\n4", "binchk: Malicious\n6"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after Malicious: %q", got)
	}
	if err := Clear(p); err != nil {
		t.Fatal(err)
	}
	if got, want := mustGet(t, p), []string{"Work", "Red\n6", "Projekt Ü\n4"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after Clear: %q", got)
	}
	// Tagging is metadata only: content, size and mtime stay the same.
	st1, _ := os.Stat(p)
	if st1.Size() != st0.Size() || !st1.ModTime().Equal(st0.ModTime()) {
		t.Fatalf("file changed: %v -> %v", st0.ModTime(), st1.ModTime())
	}

	// xattr(1) sees a binary plist ("bplist0" in hex).
	Set(p, "Malicious")
	out, err := exec.Command("xattr", "-px", attrName, p).Output()
	if err != nil || !strings.HasPrefix(strings.Join(strings.Fields(string(out)), ""), "62706C697374303") {
		t.Fatalf("xattr -px: %v %q", err, out)
	}
}

func TestClearRemovesAttribute(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tool")
	os.WriteFile(p, []byte("x"), 0o755)
	if err := Clear(p); err != nil { // nothing there: no-op
		t.Fatal(err)
	}
	if err := Set(p, "Malicious"); err != nil {
		t.Fatal(err)
	}
	if err := Clear(p); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Getxattr(p, attrName, nil); !errors.Is(err, unix.ENOATTR) {
		t.Fatalf("attribute still present: %v", err)
	}
}

func TestAppBundleAndRefusals(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "Tool.app")
	os.MkdirAll(filepath.Join(app, "Contents/MacOS"), 0o755)
	if err := Set(app, "Suspicious"); err != nil {
		t.Fatal(err)
	}
	if got := mustGet(t, app); !reflect.DeepEqual(got, []string{"binchk: Suspicious\n7"}) {
		t.Fatalf("app tags %q", got)
	}

	// Symlinks are never followed, plain directories are not tagged.
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("x"), 0o644)
	link := filepath.Join(dir, "link")
	os.Symlink(target, link)
	if err := Set(link, "Malicious"); err == nil {
		t.Fatal("tagged through a symlink")
	}
	if tags := mustGet(t, target); len(tags) != 0 {
		t.Fatalf("symlink target tagged: %q", tags)
	}
	linkApp := filepath.Join(dir, "Link.app")
	os.Symlink(app, linkApp)
	if err := Set(linkApp, "Malicious"); err == nil {
		t.Fatal("tagged through a symlinked bundle")
	}
	if err := Set(filepath.Join(dir, "Contents"), "Malicious"); err == nil {
		t.Fatal("tagged a missing path")
	}
	os.Mkdir(filepath.Join(dir, "folder"), 0o755)
	if err := Set(filepath.Join(dir, "folder"), "Malicious"); err == nil {
		t.Fatal("tagged a plain folder")
	}
}

func TestUnreadableTagsLeftAlone(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tool")
	os.WriteFile(p, []byte("x"), 0o644)
	junk := []byte("not a plist")
	unix.Setxattr(p, attrName, junk, 0)
	if err := Set(p, "Malicious"); err == nil {
		t.Fatal("overwrote tags it could not read")
	}
	buf := make([]byte, 64)
	n, _ := unix.Getxattr(p, attrName, buf)
	if string(buf[:n]) != string(junk) {
		t.Fatalf("attribute changed: %q", buf[:n])
	}
}

// Read-only downloads (and read-only app bundles) are still tagged, and keep
// their exact mode afterwards.
func TestReadOnlyStillTagged(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "ro.bin")
	os.WriteFile(f, []byte("x"), 0o444)
	os.Chmod(f, 0o444)
	app := filepath.Join(d, "RO.app")
	os.MkdirAll(filepath.Join(app, "Contents"), 0o755)
	os.Chmod(app, 0o555)
	defer os.Chmod(app, 0o755)
	for _, p := range []string{f, app} {
		before, _ := os.Stat(p)
		if err := Set(p, "Malicious"); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if got := mustGet(t, p); len(got) != 1 || got[0] != "binchk: Malicious\n6" {
			t.Errorf("%s: tags %q", p, got)
		}
		if err := Clear(p); err != nil {
			t.Fatalf("%s clear: %v", p, err)
		}
		after, _ := os.Stat(p)
		if after.Mode() != before.Mode() || !after.ModTime().Equal(before.ModTime()) {
			t.Errorf("%s: mode/mtime changed: %v %v -> %v %v", p, before.Mode(), before.ModTime(), after.Mode(), after.ModTime())
		}
	}
}
