package bundleid

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// VectorFingerprint is the fingerprint of the bundle makeVector builds. The
// Quick Look harness (macos/QuickLook/Tests/main.swift) builds the same
// bundle and asserts the same value, so the two implementations cannot
// drift apart.
const VectorFingerprint = "1d8f31b6913db5d53d3d478a16d60e1d1ae00cac889ac399bc2e45de22688466"

// VectorMainSHA256 is the SHA-256 of the vector's main executable.
const VectorMainSHA256 = "da4181a93733269869e10cd396dacad3eff5c8f4713ffe53bf946ddcdd196904"

// makeVector builds the cross-language test bundle under dir. Keep it in
// step with makeVector in macos/QuickLook/Tests/main.swift.
func makeVector(t *testing.T, dir string) string {
	t.Helper()
	app := filepath.Join(dir, "Vector.app")
	files := []struct{ path, data string }{
		{"Contents/Info.plist", `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleExecutable</key><string>Vector</string></dict></plist>
`},
		{"Contents/MacOS/Vector", "vector main executable\n"},
		{"Contents/_CodeSignature/CodeResources", "code resources\n"},
		{"Contents/Resources/a.txt", "alpha"},
		{"Contents/Resources/b/x", ""},
		{"Contents/Resources/café.txt", "unicode"},
	}
	for _, f := range files {
		p := filepath.Join(app, filepath.FromSlash(f.path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(f.data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(app, "Contents/Resources/b-c"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, l := range []struct{ path, target string }{
		{"Contents/Resources/link", "../MacOS/Vector"},
		{"Contents/Resources/dangling", "nowhere/at all"},
	} {
		if err := os.Symlink(l.target, filepath.Join(app, filepath.FromSlash(l.path))); err != nil {
			t.Fatal(err)
		}
	}
	return app
}

func fileSHA(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestVector(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links")
	}
	app := makeVector(t, t.TempDir())
	main := fileSHA(t, filepath.Join(app, "Contents/MacOS/Vector"))
	if main != VectorMainSHA256 {
		t.Errorf("main executable SHA-256 %s", main)
	}
	m, err := Manifest(app)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, e := range m {
		lines = append(lines, e.Path+" "+string(e.Type)+" "+e.Value)
	}
	want := []string{
		"Contents d ",
		"Contents/Info.plist f 134",
		"Contents/MacOS d ",
		"Contents/MacOS/Vector f 23",
		"Contents/Resources d ",
		"Contents/Resources/a.txt f 5",
		"Contents/Resources/b d ",
		"Contents/Resources/b-c d ",
		"Contents/Resources/b/x f 0",
		"Contents/Resources/café.txt f 7",
		"Contents/Resources/dangling l nowhere/at all",
		"Contents/Resources/link l ../MacOS/Vector",
		"Contents/_CodeSignature d ",
		"Contents/_CodeSignature/CodeResources f 15",
	}
	if len(lines) != len(want) {
		t.Fatalf("manifest:\n%q", lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("manifest[%d] = %q, want %q", i, lines[i], want[i])
		}
	}
	fp, err := Fingerprint(app, main)
	if err != nil {
		t.Fatal(err)
	}
	if fp != VectorFingerprint {
		t.Errorf("fingerprint %s, want %s", fp, VectorFingerprint)
	}
	// The same bundle through a symbolic link, or copied elsewhere, has the
	// same fingerprint.
	link := filepath.Join(t.TempDir(), "Linked.app")
	os.Symlink(app, link)
	if got, err := Fingerprint(link, main); err != nil || got != fp {
		t.Errorf("through a link: %s %v", got, err)
	}
	if got, _ := Fingerprint(makeVector(t, t.TempDir()), main); got != fp {
		t.Errorf("rebuilt elsewhere: %s", got)
	}
}

// Everything the fingerprint covers changes it.
func TestFingerprintChanges(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links")
	}
	main := VectorMainSHA256
	for _, c := range []struct {
		name   string
		change func(app string) error
		main   string
	}{
		{"main executable hash", func(string) error { return nil }, sha("other")},
		{"added file", func(app string) error {
			return os.WriteFile(filepath.Join(app, "Contents/Frameworks.dylib"), nil, 0o644)
		}, main},
		{"added directory", func(app string) error { return os.Mkdir(filepath.Join(app, "Contents/Frameworks"), 0o755) }, main},
		{"file size", func(app string) error {
			return os.WriteFile(filepath.Join(app, "Contents/Resources/a.txt"), []byte("alpha!"), 0o644)
		}, main},
		{"renamed file", func(app string) error {
			return os.Rename(filepath.Join(app, "Contents/Resources/a.txt"), filepath.Join(app, "Contents/Resources/A.txt"))
		}, main},
		{"link target", func(app string) error {
			p := filepath.Join(app, "Contents/Resources/link")
			os.Remove(p)
			return os.Symlink("../MacOS/Other", p)
		}, main},
		{"link replaced by file", func(app string) error {
			p := filepath.Join(app, "Contents/Resources/link")
			os.Remove(p)
			return os.WriteFile(p, []byte("../MacOS/Vector"), 0o644)
		}, main},
		{"seal content", func(app string) error {
			return os.WriteFile(filepath.Join(app, "Contents/_CodeSignature/CodeResources"), []byte("code resourceX\n"), 0o644)
		}, main},
		{"seal removed", func(app string) error {
			return os.Remove(filepath.Join(app, "Contents/_CodeSignature/CodeResources"))
		}, main},
	} {
		app := makeVector(t, t.TempDir())
		if err := c.change(app); err != nil {
			t.Fatal(err)
		}
		got, err := Fingerprint(app, c.main)
		if err != nil || got == VectorFingerprint {
			t.Errorf("%s: fingerprint unchanged (%v)", c.name, err)
		}
	}
	// A symlinked seal is not followed: it hashes as absent.
	app := makeVector(t, t.TempDir())
	seal := filepath.Join(app, "Contents/_CodeSignature/CodeResources")
	other := filepath.Join(t.TempDir(), "cr")
	os.WriteFile(other, []byte("code resources\n"), 0o644)
	os.Remove(seal)
	os.Symlink(other, seal)
	if got, _ := codeResources(app); got != NoCodeResources {
		t.Errorf("symlinked seal hashed: %s", got)
	}
	if _, err := Fingerprint(app, "short"); err == nil {
		t.Error("accepted a malformed main executable hash")
	}
	if _, err := Fingerprint(filepath.Join(app, "Contents/Info.plist"), main); err == nil {
		t.Error("fingerprinted a file")
	}
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestValidExecutableName(t *testing.T) {
	for name, ok := range map[string]bool{
		"Tool": true, "Foo Helper": true, ".hidden": true, "a\\b": true,
		"": false, ".": false, "..": false, "../x": false, "../../../benign-outside": false, "a/b": false, "/abs": false, "x\x00": false,
	} {
		if got := ValidExecutableName(name); got != ok {
			t.Errorf("ValidExecutableName(%q) = %v", name, got)
		}
	}
}

func TestSummarize(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links")
	}
	app := makeVector(t, t.TempDir())
	s := Summarize(app)
	if s.Entries != 15 || s.Size <= 0 || s.MtimeUnixNs <= 0 {
		t.Fatalf("%+v", s)
	}
	os.WriteFile(filepath.Join(app, "Contents/new"), nil, 0o644)
	if s2 := Summarize(app); s2.Entries != 16 || s2 == s {
		t.Fatalf("%+v after adding a file", s2)
	}
}
