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
	"runtime"
	"strings"
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

// Links whose lexical target stays inside the root but whose real
// resolution, through earlier links, climbs out of it must not survive.
func TestExtractCPIOSymlinkResolvedEscape(t *testing.T) {
	var arc bytes.Buffer
	arc.Write(odc("./q", 0o120777, []byte(".")))
	arc.Write(odc("./p", 0o120777, []byte("q/..")))           // really the parent of root
	arc.Write(odc("./d/r", 0o120777, []byte("../q/../q/.."))) // same, from a subdirectory
	arc.Write(odc("./w", 0o120777, []byte("q/q/q/..")))       // same, through repeated links
	// Order-dependent: v is created before u exists.
	arc.Write(odc("./v", 0o120777, []byte("u/..")))
	arc.Write(odc("./u", 0o120777, []byte(".")))
	// A link through a link that points at the root's parent.
	arc.Write(odc("./up", 0o120777, []byte("u/../..")))
	// Loop.
	arc.Write(odc("./l1", 0o120777, []byte("l2")))
	arc.Write(odc("./l2", 0o120777, []byte("l1")))
	// Legitimate in-root links.
	arc.Write(odc("./fw/Versions/A/Fw", 0o100644, []byte("lib")))
	arc.Write(odc("./fw/Versions/Current", 0o120777, []byte("A")))
	arc.Write(odc("./fw/Fw", 0o120777, []byte("Versions/Current/Fw")))
	arc.Write(odc("./fw/Res", 0o120777, []byte("Versions/Current/../A/Fw")))
	arc.Write(odc("./dangling", 0o120777, []byte("missing/file")))
	arc.Write(odc("TRAILER!!!", 0, nil))
	base := t.TempDir()
	dir := filepath.Join(base, "x")
	if _, err := ExtractCPIO(context.Background(), &arc, dir, Limits{MaxBytes: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	rootReal, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.Type()&os.ModeSymlink == 0 {
			return err
		}
		r, err := filepath.EvalSymlinks(p)
		if err != nil {
			return nil // dangling or looping: cannot be followed anywhere
		}
		if rel, err := filepath.Rel(rootReal, r); err != nil || !filepath.IsLocal(rel) && rel != "." {
			t.Errorf("%s resolves outside the root: %s", p, r)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"p", "d/r", "w", "v", "up"} {
		if _, err := os.Lstat(filepath.Join(dir, l)); err == nil {
			t.Errorf("escaping symlink %s was kept", l)
		}
	}
	for _, l := range []string{"fw/Fw", "fw/Res"} {
		if b, err := os.ReadFile(filepath.Join(dir, l)); err != nil || string(b) != "lib" {
			t.Errorf("in-root link %s: %q %v", l, b, err)
		}
	}
	for _, l := range []string{"q", "u", "dangling"} {
		if _, err := os.Lstat(filepath.Join(dir, l)); err != nil {
			t.Errorf("harmless link %s was removed: %v", l, err)
		}
	}
}

// zeroStream is an endless run of zero bytes: to pbzx, empty chunks forever.
type zeroStream struct{}

func (zeroStream) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// The pbzx chunk loop honours ctx even when no chunk yields data.
func TestPBZXHonoursContext(t *testing.T) {
	hdr := append([]byte("pbzx"), make([]byte, 8)...)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	pr, err := PayloadReaderContext(ctx, io.MultiReader(bytes.NewReader(hdr), zeroStream{}))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := pr.Read(make([]byte, 16)); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("err = %v, want deadline exceeded", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pbzx Read ignored the context")
	}
}

// assertConfined fails t if any symlink under dir resolves outside it.
func assertConfined(t *testing.T, dir string) {
	t.Helper()
	rootReal, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.Type()&os.ModeSymlink == 0 {
			return nil
		}
		r, err := filepath.EvalSymlinks(p)
		if err != nil {
			return nil // dangling or looping: cannot be followed anywhere
		}
		if rel, err := filepath.Rel(rootReal, r); err != nil || !filepath.IsLocal(rel) && rel != "." {
			t.Errorf("%s resolves outside %s: %s", p, dir, r)
		}
		return nil
	})
}

// cpio builds an odc archive from entries, adding the trailer.
func cpio(entries ...[]byte) *bytes.Buffer {
	var b bytes.Buffer
	for _, e := range entries {
		b.Write(e)
	}
	b.Write(odc("TRAILER!!!", 0, nil))
	return &b
}

// A second extraction into the same directory must not turn a link the
// first one kept (lexically in-root through a missing component) into an
// escape: every link in the final tree is re-checked, not just new ones.
func TestExtractCPIOSameDirTwice(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "x")
	deep := strings.Repeat("u/", 12) + strings.Repeat("../", 12)
	first := cpio(odc("./v", 0o120777, []byte(deep)), odc("./ok", 0o120777, []byte("u")))
	if _, err := ExtractCPIO(context.Background(), first, dir, Limits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "v")); err != nil {
		t.Fatalf("in-root link v was dropped by the first extraction: %v", err)
	}
	second := cpio(odc("./u", 0o120777, []byte(".")))
	if _, err := ExtractCPIO(context.Background(), second, dir, Limits{}); err != nil {
		t.Fatal(err)
	}
	assertConfined(t, dir)
	if _, err := os.Lstat(filepath.Join(dir, "v")); err == nil {
		t.Error("link v, now escaping through u, was kept")
	}
	if _, err := os.Lstat(filepath.Join(dir, "ok")); err != nil {
		t.Errorf("harmless link ok was removed: %v", err)
	}
}

// Targets carrying the other platform's separator: on Windows "\" splits
// components (and a leading one is rooted); elsewhere it is part of a
// file name. Either way nothing may resolve outside the root.
func TestExtractCPIOBackslashTargets(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "x")
	arc := cpio(
		odc("./q", 0o120777, []byte(".")),
		odc("./a/b1", 0o120777, []byte(`..\..\..\etc`)),
		odc("./a/b2", 0o120777, []byte(`q\..\..`)),
		odc("./a/b3", 0o120777, []byte(`\etc\passwd`)),
		odc("./a/b4", 0o120777, []byte(`C:\Windows`)),
		odc("./a/b5", 0o120777, []byte(`..\q\..\..`)),
		odc("./a/b6", 0o120777, []byte(`../q\../..`)),
		odc("./a/b7", 0o120777, []byte(`..\..`)),
	)
	if _, err := ExtractCPIO(context.Background(), arc, dir, Limits{}); err != nil {
		t.Fatal(err)
	}
	assertConfined(t, dir)
	want := map[string]bool{ // kept?
		"a/b1": runtime.GOOS != "windows", // one odd file name elsewhere
		"a/b3": runtime.GOOS != "windows",
		"a/b4": runtime.GOOS != "windows",
		"a/b6": runtime.GOOS != "windows", // ../ then a name "q\.." then ..
		"a/b7": runtime.GOOS != "windows",
	}
	for l, keep := range want {
		_, err := os.Lstat(filepath.Join(dir, l))
		if kept := err == nil; kept != keep {
			t.Errorf("link %s kept = %v, want %v", l, kept, keep)
		}
	}
}

// A link needing more hops than the kernel follows is refused (fails
// closed) while a chain within the limit is kept.
func TestExtractCPIOHopLimit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "x")
	// c0 -> f, cN -> c(N-1): resolving cN's target takes N hops.
	es := [][]byte{odc("./f", 0o100644, []byte("data")), odc("./c0", 0o120777, []byte("f"))}
	for i := 1; i <= maxLinkHops+2; i++ {
		es = append(es, odc(fmt.Sprintf("./c%d", i), 0o120777, []byte(fmt.Sprintf("c%d", i-1))))
	}
	if _, err := ExtractCPIO(context.Background(), cpio(es...), dir, Limits{}); err != nil {
		t.Fatal(err)
	}
	assertConfined(t, dir)
	// Opening cI follows I+1 links; the kernel stops at maxLinkHops.
	for i := 0; i <= maxLinkHops+1; i++ {
		c := filepath.Join(dir, fmt.Sprintf("c%d", i))
		_, err := os.Lstat(c)
		if kept, keep := err == nil, i+1 <= maxLinkHops; kept != keep {
			t.Errorf("c%d kept = %v, want %v", i, kept, keep)
		}
		if i == 9 { // kept links work; near the limit the kernel may stop sooner
			if b, err := os.ReadFile(c); err != nil || string(b) != "data" {
				t.Errorf("chain of %d links: %q %v", i+1, b, err)
			}
		}
	}
	// The next link points at a refused one: it stays, dangling.
	if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("c%d", maxLinkHops+2))); err == nil {
		t.Errorf("c%d resolves", maxLinkHops+2)
	}
}

// Once the resolution budget is spent, remaining links are refused and
// kept ones dropped, but regular files are still extracted and nothing
// escapes. Each link below costs about 2000 components per check.
func TestExtractCPIOLinkBudgetExhausted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "x")
	long := []byte(strings.Repeat("./", 2000) + "f")
	n := linkBudget/2000 + 10
	es := [][]byte{odc("./f", 0o100644, []byte("data"))}
	for i := 0; i < n; i++ {
		es = append(es, odc(fmt.Sprintf("./l%d", i), 0o120777, long))
	}
	es = append(es, odc("./q", 0o120777, []byte(".")), odc("./esc", 0o120777, []byte("q/..")))
	es = append(es, odc("./late", 0o100644, []byte("late")))
	if _, err := ExtractCPIO(context.Background(), cpio(es...), dir, Limits{}); err != nil {
		t.Fatal(err)
	}
	assertConfined(t, dir)
	if b, err := os.ReadFile(filepath.Join(dir, "late")); err != nil || string(b) != "late" {
		t.Errorf("regular file after budget exhaustion: %q %v", b, err)
	}
	for _, l := range []string{"l0", fmt.Sprintf("l%d", n-1), "q", "esc"} {
		if _, err := os.Lstat(filepath.Join(dir, l)); err == nil {
			t.Errorf("link %s kept although the budget ran out", l)
		}
	}
}
