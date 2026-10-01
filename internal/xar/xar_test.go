package xar

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
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

// writeXar writes a xar archive whose TOC is the zlib-compressed output of
// toc, declaring uncomp as its uncompressed length (len of the XML if 0).
func writeXar(t *testing.T, toc func(io.Writer), uncomp uint64) string {
	t.Helper()
	var z bytes.Buffer
	zw, _ := zlib.NewWriterLevel(&z, zlib.BestCompression)
	cw := &countWriter{w: zw}
	toc(cw)
	zw.Close()
	if uncomp == 0 {
		uncomp = uint64(cw.n)
	}
	var b bytes.Buffer
	b.WriteString("xar!")
	binary.Write(&b, binary.BigEndian, struct {
		HeaderSize  uint16
		Version     uint16
		TOCCompLen  uint64
		TOCUncompLn uint64
		ChecksumAlg uint32
	}{28, 1, uint64(z.Len()), uncomp, 0})
	b.Write(z.Bytes())
	p := filepath.Join(t.TempDir(), "t.pkg")
	if err := os.WriteFile(p, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.n += int64(n)
	return n, err
}

func xmlTOC(s string) func(io.Writer) {
	return func(w io.Writer) { io.WriteString(w, s) }
}

func TestTOCParse(t *testing.T) {
	p := writeXar(t, xmlTOC(`<?xml version="1.0" encoding="UTF-8"?>
<xar><toc><checksum style="sha1"><offset>0</offset><size>20</size></checksum>
<signature style="RSA"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>bm90IGEgY2VydA==</X509Certificate></X509Data></KeyInfo></signature>
<file id="1"><name>Distribution</name><type>file</type>
 <data><length>10</length><encoding style="application/x-gzip"/><offset>20</offset><size>30</size></data></file>
<file id="2"><type>directory</type>
 <file id="3"><name>Payload</name><type>file</type><data><offset> 40 </offset><length>5</length><size>6</size>
  <encoding style="application/octet-stream"/></data></file>
 <file id="4"><name>link</name><type>symlink</type><link>Payload</link></file>
 <name>a.pkg</name></file>
</toc></xar>`), 0)
	a, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	want := []Entry{
		{Path: "Distribution", Type: "file", Offset: 20, Length: 10, Size: 30, Encoding: "application/x-gzip"},
		{Path: "a.pkg", Type: "directory"},
		{Path: "a.pkg/Payload", Type: "file", Offset: 40, Length: 5, Size: 6, Encoding: "application/octet-stream"},
		{Path: "a.pkg/link", Type: "symlink", Link: "Payload"},
	}
	if fmt.Sprint(a.Entries) != fmt.Sprint(want) {
		t.Errorf("entries:\n got %+v\nwant %+v", a.Entries, want)
	}
	if a.SigStyle != "RSA" || len(a.Certs) != 0 {
		t.Errorf("sig style %q", a.SigStyle)
	}
}

// A tiny archive whose TOC inflates to tens of MiB of <file> elements must be
// rejected quickly without materialising it.
func TestTOCBombRejected(t *testing.T) {
	huge := func(w io.Writer) {
		io.WriteString(w, "<xar><toc>")
		chunk := []byte(strings.Repeat("<file><name>a</name></file>", 1<<12))
		for range 100 { // ~11 MiB
			w.Write(chunk)
		}
		io.WriteString(w, "</toc></xar>")
	}
	bombs := map[string]string{
		"huge": writeXar(t, huge, 0),
		// Declares a plausible size; inflation must stop there regardless.
		"lying": writeXar(t, huge, 1<<20),
		// Varied names keep these within the size and ratio limits so the
		// streaming caps are what reject them.
		"entries": writeXar(t, func(w io.Writer) {
			io.WriteString(w, "<xar><toc>")
			for i := range 20000 {
				fmt.Fprintf(w, "<file><name>%x</name></file>", uint32(i)*2654435761)
			}
			io.WriteString(w, "</toc></xar>")
		}, 0),
		"ratio": writeXar(t, xmlTOC("<xar><toc>"+strings.Repeat("<file><name>a</name></file>", 60000)+"</toc></xar>"), 0),
		"depth": writeXar(t, xmlTOC("<xar><toc>"+strings.Repeat("<file>", 1000)+strings.Repeat("</file>", 1000)+"</toc></xar>"), 0),
		// Each child's path copies its parent's, so one long directory name,
		// or a chain of moderate ones, is amplified per descendant. Random
		// junk keeps the ratio plausible.
		"longname": writeXar(t, func(w io.Writer) {
			io.WriteString(w, "<xar><toc>")
			writeJunk(w)
			io.WriteString(w, "<file><name>"+strings.Repeat("A", 3<<20)+"</name>")
			io.WriteString(w, strings.Repeat("<file><name>a</name></file>", 1600))
			io.WriteString(w, "</file></toc></xar>")
		}, 0),
		"name": writeXar(t, xmlTOC("<xar><toc><file><name>"+strings.Repeat("C", 2000)+"</name></file></toc></xar>"), 0),
		// An over-long end tag name, and a long tag spread over attributes
		// whose values hide '>'.
		"endtag": writeXar(t, func(w io.Writer) {
			io.WriteString(w, "<xar><toc>")
			writeJunk(w)
			io.WriteString(w, "</"+strings.Repeat("E", 3<<20)+"></toc></xar>")
		}, 0),
		"gtattrs": writeXar(t, func(w io.Writer) {
			io.WriteString(w, "<xar><toc>")
			writeJunk(w)
			io.WriteString(w, "<a"+strings.Repeat(` a=">"`, 600000)+"/></toc></xar>")
		}, 0),
		// One start tag holding hundreds of thousands of attributes: a
		// decoder that materialises them amplifies the TOC many times over.
		"attrs": writeXar(t, func(w io.Writer) {
			io.WriteString(w, "<xar><toc>")
			writeJunk(w)
			io.WriteString(w, "<a"+strings.Repeat(` a=""`, 780000)+"/></toc></xar>")
		}, 0),
		// Deeply nested unknown elements with long tag names: per-element
		// paths would grow with depth squared times name length.
		"tagnames": writeXar(t, func(w io.Writer) {
			io.WriteString(w, "<xar><toc>")
			writeJunk(w)
			tag := strings.Repeat("T", 30000)
			io.WriteString(w, strings.Repeat("<"+tag+">", 62)+strings.Repeat("</"+tag+">", 62))
			io.WriteString(w, "</toc></xar>")
		}, 0),
		"paths": writeXar(t, func(w io.Writer) {
			io.WriteString(w, "<xar><toc>")
			writeJunk(w)
			for i := range 30 {
				fmt.Fprintf(w, "<file><name>%d%s</name>", i, strings.Repeat("B", 1000))
			}
			io.WriteString(w, strings.Repeat("<file><name>a</name></file>", 9000))
			io.WriteString(w, strings.Repeat("</file>", 30)+"</toc></xar>")
		}, 0),
	}
	for name, p := range bombs {
		if st, _ := os.Stat(p); st.Size() > 256<<10 {
			t.Fatalf("%s: bomb is %d bytes, want tiny", name, st.Size())
		}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		t0 := time.Now()
		a, err := Open(p)
		el := time.Since(t0)
		runtime.ReadMemStats(&after)
		if err == nil {
			a.Close()
			t.Errorf("%s: bomb accepted with %d entries", name, len(a.Entries))
		} else {
			t.Logf("%s: %v (%v, allocated %d KiB)", name, err, el, (after.TotalAlloc-before.TotalAlloc)>>10)
		}
		if d := after.TotalAlloc - before.TotalAlloc; d > maxBombAlloc {
			t.Errorf("%s: Open allocated %d MiB", name, d>>20)
		}
		if el > 5*time.Second {
			t.Errorf("%s: Open took %v", name, el)
		}
	}
}

// maxBombAlloc bounds what parsing any crafted TOC may allocate: a small
// multiple of the TOC caps, whatever the XML shape.
const maxBombAlloc = 16 << 20

// Markup that stays within every per-tag limit but is repeated to fill the
// TOC must still cost memory proportional to what is kept, not to its size.
func TestTOCMarkupWithinLimitsIsCheap(t *testing.T) {
	attrs := strings.Repeat(` a="x"`, 600) // ~3.6 KiB per tag
	tag := strings.Repeat("T", 250)
	shapes := map[string]func(io.Writer){
		"attrs": func(w io.Writer) {
			io.WriteString(w, "<xar><toc>")
			writeJunk(w)
			for range 250 {
				io.WriteString(w, "<file"+attrs+"><name"+attrs+">n</name><data"+attrs+"><encoding"+attrs+" style='s'/></data></file>")
			}
			io.WriteString(w, "</toc></xar>")
		},
		"names": func(w io.Writer) {
			io.WriteString(w, "<xar><toc>")
			writeJunk(w)
			for range 120 {
				io.WriteString(w, strings.Repeat("<"+tag+">", 60)+strings.Repeat("</"+tag+">", 60))
			}
			io.WriteString(w, "</toc></xar>")
		},
	}
	for name, toc := range shapes {
		p := writeXar(t, toc, 0)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		a, err := Open(p)
		runtime.ReadMemStats(&after)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		a.Close()
		d := after.TotalAlloc - before.TotalAlloc
		t.Logf("%s: %d entries, allocated %d KiB", name, len(a.Entries), d>>10)
		if d > 2<<20 {
			t.Errorf("%s: Open allocated %d KiB", name, d>>10)
		}
	}
}

// refFile mirrors the TOC with xml.Unmarshal, which the streaming parser
// must agree with on every element it keeps.
type refFile struct {
	Name string `xml:"name"`
	Type string `xml:"type"`
	Link string `xml:"link"`
	Data struct {
		Offset   string `xml:"offset"`
		Length   string `xml:"length"`
		Size     string `xml:"size"`
		Encoding struct {
			Style string `xml:"style,attr"`
		} `xml:"encoding"`
	} `xml:"data"`
	Files []refFile `xml:"file"`
}

type refSig struct {
	Style string   `xml:"style,attr"`
	Certs []string `xml:"KeyInfo>X509Data>X509Certificate"`
}

func refEntries(dir string, fs []refFile, out []Entry) []Entry {
	for _, f := range fs {
		p := path.Join(dir, f.Name)
		off, _ := parseInt(f.Data.Offset)
		ln, _ := parseInt(f.Data.Length)
		sz, _ := parseInt(f.Data.Size)
		out = append(out, Entry{Path: p, Type: f.Type, Offset: off, Length: ln, Size: sz, Encoding: f.Data.Encoding.Style, Link: f.Link})
		out = refEntries(p, f.Files, out)
	}
	return out
}

func TestTOCMatchesUnmarshal(t *testing.T) {
	tocs := []string{
		// Text interrupted by child elements, comments and PIs is joined.
		`<xar><toc><file><name>ab<x>zz</x>cd</name><type>fi<!-- c -->le</type><link>l<?pi x?>k</link></file></toc></xar>`,
		// References, CDATA, line ends, namespaces, single quotes, spaces.
		"<?xml version='1.0'?>\n<!-- lead -->\n<xar>\r\n<toc ><file id='1'\n><name>a&amp;b&#65;&#x42;&lt;&gt;&quot;&apos;</name>" +
			"<type><![CDATA[x]y]]z]]]></type><link>l1\r\nl2\rl3</link>" +
			"<data ><offset > 7 </offset><length/><size>9</size><encoding a=\"1\" style = 'q&amp;r' style2='z' /></data></file>" +
			"<x:file xmlns:x='urn:x'><x:name>ns</x:name></x:file></toc></xar>",
		// Repeated elements: the last wins; nested and sibling files.
		`<r><toc><file><name>a</name><name>b</name><file><name>c</name><file><name>d</name></file></file></file>` +
			`<file><name>e</name><data><encoding style="1"/><encoding style="2"/></data></file></toc></r>`,
		// Files and names outside the places they count are ignored.
		`<xar><file><name>no</name></file><toc><other><file><name>no</name></file></other>` +
			`<file><data><file><name>no</name></file></data><name>yes</name></file></toc></xar>`,
		// Signatures.
		`<xar><toc><signature style="RSA" other="1"><KeyInfo><X509Data><X509Certificate>QUJD</X509Certificate>` +
			`<X509Certificate>REVG</X509Certificate></X509Data></KeyInfo></signature>` +
			`<x-signature style="CMS"/></toc></xar>`,
	}
	for i, doc := range tocs {
		var ref struct {
			Files []refFile `xml:"toc>file"`
			Sig   []refSig  `xml:"toc>signature"`
			XSig  []refSig  `xml:"toc>x-signature"`
		}
		if err := xml.Unmarshal([]byte(doc), &ref); err != nil {
			t.Fatalf("%d: reference: %v", i, err)
		}
		a := &Archive{}
		if err := a.parseTOC(strings.NewReader(doc)); err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}
		want := refEntries("", ref.Files, nil)
		if !reflect.DeepEqual(a.Entries, want) {
			t.Errorf("%d: entries\n got %#v\nwant %#v", i, a.Entries, want)
		}
		wantStyle := ""
		for _, s := range append(ref.Sig, ref.XSig...) {
			if wantStyle == "" {
				wantStyle = s.Style
			}
		}
		if a.SigStyle != wantStyle {
			t.Errorf("%d: sig style %q, want %q", i, a.SigStyle, wantStyle)
		}
	}
}

func TestTOCMalformedRejected(t *testing.T) {
	for _, doc := range []string{
		`<xar><toc></xar></toc>`,
		`<xar><toc><file><name>a</name></file></toc>`,
		`<xar><toc><file><name>a&bogus;</name></file></toc></xar>`,
		`<xar><toc><file><name>a&#0;</name></file></toc></xar>`,
		`<xar><toc><file a=b><name>a</name></file></toc></xar>`,
		`<xar><toc><file a="<"><name>a</name></file></toc></xar>`,
		`<xar><toc><file a="1"b="2"></file></toc></xar>`,
		`<!DOCTYPE x [<!ENTITY e "boom">]><xar><toc></toc></xar>`,
		`<xar><toc><file><name>a<![CDATA[b</name></file></toc></xar>`,
		`<xar><toc><file><name>a<!-- b</name></file></toc></xar>`,
		"<xar><toc><file><name>\xff</name></file></toc></xar>",
		`</xar>`,
		``,
	} {
		if err := (&Archive{}).parseTOC(strings.NewReader(doc)); err == nil {
			t.Errorf("accepted %q", doc)
		}
	}
}

// writeJunk writes an element holding 80 KiB of incompressible hex.
func writeJunk(w io.Writer) {
	b := make([]byte, 80<<10)
	rand.NewChaCha8([32]byte{1}).Read(b)
	io.WriteString(w, "<junk>"+hex.EncodeToString(b)+"</junk>")
}
