package xar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// odc builds a cpio (odc) entry.
func odc(name string, mode uint32, data []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "070707%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o", 0, 0, mode, 0, 0, 1, 0, 0, len(name)+1, len(data))
	b.WriteString(name + "\x00")
	b.Write(data)
	return b.Bytes()
}

func TestExtractCPIOIsConfined(t *testing.T) {
	var arc bytes.Buffer
	arc.Write(odc("./ok/file.txt", 0o100755|0o4000, []byte("hello")))
	arc.Write(odc("../../escape.txt", 0o100644, []byte("nope")))
	arc.Write(odc("./link-in", 0o120777, []byte("ok/file.txt")))
	arc.Write(odc("./ok/link-out", 0o120777, []byte("../../../etc/passwd")))
	arc.Write(odc("./abs-link", 0o120777, []byte("/etc/passwd")))
	arc.Write(odc("TRAILER!!!", 0, nil))
	root := t.TempDir()
	dir := filepath.Join(root, "x")
	if _, err := ExtractCPIO(context.Background(), &arc, dir, Limits{MaxBytes: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "ok/file.txt"))
	if err != nil || st.Mode()&os.ModeSetuid != 0 {
		t.Fatalf("file: %v %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(root, "escape.txt")); err == nil {
		t.Fatal("path traversal escaped the root")
	}
	if _, err := os.Lstat(filepath.Join(dir, "link-in")); err != nil {
		t.Error("in-root symlink should be created")
	}
	for _, l := range []string{"ok/link-out", "abs-link"} {
		if _, err := os.Lstat(filepath.Join(dir, l)); err == nil {
			t.Errorf("escaping symlink %s was created", l)
		}
	}
	// byte budget
	var big bytes.Buffer
	big.Write(odc("./a", 0o100644, make([]byte, 2048)))
	big.Write(odc("TRAILER!!!", 0, nil))
	if _, err := ExtractCPIO(context.Background(), &big, t.TempDir(), Limits{MaxBytes: 1024}); err == nil {
		t.Fatal("expected limit error")
	}
}

// A chain of symlinks that each pass the lexical in-root check must not let a
// later entry write outside the extraction root.
func TestExtractCPIOSymlinkChain(t *testing.T) {
	var arc bytes.Buffer
	arc.Write(odc("./a/b", 0o040755, nil))
	arc.Write(odc("./a/b/l", 0o120777, []byte("..")))      // -> a
	arc.Write(odc("./a/b/l/m", 0o120777, []byte("../.."))) // really a/m -> outside
	arc.Write(odc("./a/b/l/m/escape.txt", 0o100644, []byte("pwned")))
	arc.Write(odc("./a/b/l/m/sub", 0o040755, nil))
	arc.Write(odc("./fw/Versions/A/Fw", 0o100644, []byte("lib")))
	arc.Write(odc("./fw/Versions/Current", 0o120777, []byte("A")))
	arc.Write(odc("./fw/Fw", 0o120777, []byte("Versions/Current/Fw")))
	arc.Write(odc("TRAILER!!!", 0, nil))
	base := t.TempDir()
	dir := filepath.Join(base, "x")
	ExtractCPIO(context.Background(), &arc, dir, Limits{MaxBytes: 1 << 20})
	for _, p := range []string{"escape.txt", "sub"} {
		if _, err := os.Lstat(filepath.Join(base, p)); err == nil {
			t.Errorf("%s was written outside the extraction root", p)
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "fw/Fw")); err != nil || string(b) != "lib" {
		t.Errorf("in-root framework symlinks: %q %v", b, err)
	}
}

// slowZeros yields zeros slowly, standing in for a decompression bomb.
type slowZeros struct{}

func (slowZeros) Read(p []byte) (int, error) {
	time.Sleep(time.Millisecond)
	clear(p)
	return len(p), nil
}

// A huge non-regular entry is drained under the deadline and the byte budget.
func TestExtractCPIOBodyBounded(t *testing.T) {
	bomb := func() io.Reader {
		var h bytes.Buffer
		fmt.Fprintf(&h, "070707%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o", 0, 0, 0o020644, 0, 0, 1, 0, 0, 4, int64(1)<<32)
		h.WriteString("dev\x00")
		return io.MultiReader(&h, slowZeros{})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	if _, err := ExtractCPIO(ctx, bomb(), t.TempDir(), Limits{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want deadline exceeded", err)
	}
	if d := time.Since(t0); d > time.Second {
		t.Errorf("returned after %v", d)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := ExtractCPIO(ctx, bomb(), t.TempDir(), Limits{MaxBytes: 1 << 20}); !errors.Is(err, ErrLimit) {
		t.Errorf("err = %v, want ErrLimit", err)
	}
}

// Round-trip a real package built by pkgbuild (macOS only).
func TestPkgbuildPackage(t *testing.T) {
	if _, err := exec.LookPath("pkgbuild"); err != nil {
		t.Skip("pkgbuild not available")
	}
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, "root/usr/local/bin"), 0o755)
	os.WriteFile(filepath.Join(d, "root/usr/local/bin/tool"), bytes.Repeat([]byte("binary!"), 5000), 0o755)
	os.MkdirAll(filepath.Join(d, "scripts"), 0o755)
	os.WriteFile(filepath.Join(d, "scripts/postinstall"), []byte("#!/bin/sh\necho installed\n"), 0o755)
	pkg := filepath.Join(d, "t.pkg")
	out, err := exec.Command("pkgbuild", "--root", filepath.Join(d, "root"), "--scripts", filepath.Join(d, "scripts"),
		"--identifier", "com.example.t", "--version", "1", pkg).CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	a, err := Open(pkg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	for _, part := range []string{"Payload", "Scripts"} {
		e, ok := a.Find(part)
		if !ok {
			t.Fatalf("no %s entry; entries: %+v", part, a.Entries)
		}
		rc, err := a.Open(e)
		if err != nil {
			t.Fatal(err)
		}
		pr, err := PayloadReader(rc)
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(d, "x-"+part)
		if _, err := ExtractCPIO(context.Background(), pr, dst, Limits{MaxBytes: 1 << 30}); err != nil {
			t.Fatalf("%s: %v", part, err)
		}
		rc.Close()
	}
	if b, _ := os.ReadFile(filepath.Join(d, "x-Payload/usr/local/bin/tool")); len(b) != 35000 {
		t.Errorf("payload tool: %d bytes", len(b))
	}
	if b, _ := os.ReadFile(filepath.Join(d, "x-Scripts/postinstall")); !bytes.Contains(b, []byte("installed")) {
		t.Errorf("postinstall: %q", b)
	}
}
