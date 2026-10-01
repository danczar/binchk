package container

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danczar/binchk/internal/xar"
)

// odcEntry builds one cpio (odc) entry.
func odcEntry(name string, mode uint32, data string) string {
	return fmt.Sprintf("070707%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o%s\x00%s",
		0, 0, mode, 0, 0, 1, 0, 0, len(name)+1, len(data), name, data)
}

func cpioArchive(entries ...string) string {
	return strings.Join(entries, "") + odcEntry("TRAILER!!!", 0, "")
}

// tocNode is a table-of-contents entry for writeXar: a file with data, or
// a directory with children.
type tocNode struct {
	name string
	data string
	kids []tocNode
}

// writeXar writes a minimal uncompressed-data xar archive.
func writeXar(t *testing.T, path string, nodes []tocNode) {
	t.Helper()
	var heap bytes.Buffer
	var toc strings.Builder
	id := 0
	var emit func([]tocNode)
	emit = func(ns []tocNode) {
		for _, n := range ns {
			id++
			fmt.Fprintf(&toc, `<file id="%d"><name>%s</name>`, id, n.name)
			if n.kids != nil {
				toc.WriteString(`<type>directory</type>`)
				emit(n.kids)
			} else {
				fmt.Fprintf(&toc, `<type>file</type><data><offset>%d</offset><length>%d</length><size>%d</size>`+
					`<encoding style="application/octet-stream"/></data>`, heap.Len(), len(n.data), len(n.data))
				heap.WriteString(n.data)
			}
			toc.WriteString(`</file>`)
		}
	}
	emit(nodes)
	raw := `<?xml version="1.0" encoding="UTF-8"?><xar><toc>` + toc.String() + `</toc></xar>`
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write([]byte(raw))
	zw.Close()
	var out bytes.Buffer
	binary.Write(&out, binary.BigEndian, struct {
		Magic             [4]byte
		HeaderSize, Ver   uint16
		CompLen, RawLen   uint64
		ChecksumAlgorithm uint32
	}{[4]byte{'x', 'a', 'r', '!'}, 28, 1, uint64(z.Len()), uint64(len(raw)), 0})
	out.Write(z.Bytes())
	out.Write(heap.Bytes())
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A table of contents with duplicate, nested and ".." Payload entries
// must not let one extraction change how another's links resolve, nor
// write anywhere outside the package's temporary directory.
func TestPkgPayloadDirsAreDisjoint(t *testing.T) {
	d := t.TempDir()
	deep := strings.Repeat("u/", 12) + strings.Repeat("../", 12)
	// Lexically in-root while u is missing; escapes once u -> ".".
	// w likewise, once a nested extraction adds Payload/u -> ".".
	first := cpioArchive(odcEntry("./v", 0o120777, deep), odcEntry("./w", 0o120777, "Payload/"+deep+"../"))
	second := cpioArchive(odcEntry("./u", 0o120777, "."))
	evil := cpioArchive(odcEntry("./planted", 0o100644, "x"))
	pkg := filepath.Join(d, "evil.pkg")
	writeXar(t, pkg, []tocNode{
		{name: "Payload", data: first},
		{name: "Payload", data: second},                                            // duplicate
		{name: "./Payload", data: second},                                          // same path once joined
		{name: "Payload", kids: []tocNode{{name: "Payload", data: second}}},        // nested
		{name: "../../../../evil", kids: []tocNode{{name: "Payload", data: evil}}}, // traversal
	})
	a, err := xar.Open(pkg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	tmp := filepath.Join(d, "a", "b", "tmp")
	os.MkdirAll(tmp, 0o700)
	in := &inspector{ctx: context.Background()}
	parts := payloadParts(tmp, a.Entries)
	if len(parts) != 5 {
		t.Fatalf("got %d parts, want 5: %+v", len(parts), parts)
	}
	seen := map[string]bool{}
	for _, p := range parts {
		if filepath.Dir(p.dst) != filepath.Join(tmp, "x") || seen[p.dst] {
			t.Errorf("%s: dst %s is not its own directory under %s/x", p.e.Path, p.dst, tmp)
		}
		seen[p.dst] = true
		if _, err := extract(in, a, p.e, p.dst, true); err != nil {
			t.Errorf("extract %s: %v", p.e.Path, err)
		}
	}

	rootReal, _ := filepath.EvalSymlinks(tmp)
	filepath.WalkDir(tmp, func(p string, de os.DirEntry, err error) error {
		if err != nil || de.Type()&os.ModeSymlink == 0 {
			return nil
		}
		r, err := filepath.EvalSymlinks(p)
		if err != nil {
			return nil
		}
		if rel, err := filepath.Rel(rootReal, r); err != nil || !filepath.IsLocal(rel) && rel != "." {
			t.Errorf("%s resolves outside the temporary directory: %s", p, r)
		}
		return nil
	})
	if _, err := os.Stat(filepath.Join(d, "evil")); err == nil {
		t.Error("a \"..\" entry was extracted outside the temporary directory")
	}
}
