package xar

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
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
				fmt.Fprintf(w, "<file><name>%x</name></file>", i*2654435761)
			}
			io.WriteString(w, "</toc></xar>")
		}, 0),
		"ratio": writeXar(t, xmlTOC("<xar><toc>"+strings.Repeat("<file><name>a</name></file>", 60000)+"</toc></xar>"), 0),
		"depth": writeXar(t, xmlTOC("<xar><toc>"+strings.Repeat("<file>", 1000)+strings.Repeat("</file>", 1000)+"</toc></xar>"), 0),
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
			t.Logf("%s: %v (%v)", name, err, el)
		}
		if d := after.TotalAlloc - before.TotalAlloc; d > 32<<20 {
			t.Errorf("%s: Open allocated %d MiB", name, d>>20)
		}
		if el > 5*time.Second {
			t.Errorf("%s: Open took %v", name, el)
		}
	}
}
