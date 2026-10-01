// Package xar reads xar archives (the container format of macOS flat
// installer packages) and the cpio / pbzx payloads inside them, in pure Go.
// Extraction is defensive: it never writes outside the destination, only
// creates symlinks that stay inside it, drops setuid/setgid bits, and stops
// at a byte budget so a decompression bomb cannot fill the disk.
package xar

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"compress/zlib"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
)

type Entry struct {
	Path     string // slash-separated, relative
	Type     string // file, directory, symlink
	Offset   int64  // within the heap
	Length   int64  // stored (compressed) length
	Size     int64  // extracted size
	Encoding string // MIME style of the stored data
	Link     string
}

type Archive struct {
	f        *os.File
	heap     int64
	Entries  []Entry
	Certs    []*x509.Certificate // signing chain from the TOC, if signed
	SigStyle string
}

// Bounds on the table of contents. Real installer TOCs are a few KiB (one
// entry per component file plus the signing chain) and compress about 3:1,
// so these only stop crafted archives that inflate a tiny file into a huge
// or deeply nested TOC.
const (
	maxTOCSize    = 4 << 20  // uncompressed bytes
	maxTOCRatio   = 64       // uncompressed / compressed, checked once the TOC
	maxTOCRatioAt = 64 << 10 // is larger than this
	maxTOCEntries = 10000
	maxTOCDepth   = 64 // nested elements
	maxTOCCerts   = 32
)

// Open parses the archive header and table of contents.
func Open(name string) (*Archive, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	var h struct {
		Magic       [4]byte
		HeaderSize  uint16
		Version     uint16
		TOCCompLen  uint64
		TOCUncompLn uint64
		ChecksumAlg uint32
	}
	if err := binary.Read(f, binary.BigEndian, &h); err != nil || string(h.Magic[:]) != "xar!" {
		f.Close()
		return nil, errors.New("not a xar archive")
	}
	if h.TOCCompLen > maxTOCSize || h.TOCUncompLn > maxTOCSize {
		f.Close()
		return nil, errors.New("xar table of contents too large")
	}
	if h.TOCUncompLn > maxTOCRatioAt && h.TOCUncompLn > maxTOCRatio*h.TOCCompLen {
		f.Close()
		return nil, errors.New("xar table of contents implausibly compressed")
	}
	zr, err := zlib.NewReader(io.NewSectionReader(f, int64(h.HeaderSize), int64(h.TOCCompLen)))
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("xar toc: %w", err)
	}
	a := &Archive{f: f, heap: int64(h.HeaderSize) + int64(h.TOCCompLen)}
	// Never inflate more than the declared size, which is already bounded.
	if err := a.parseTOC(io.LimitReader(zr, int64(h.TOCUncompLn))); err != nil {
		f.Close()
		return nil, fmt.Errorf("xar toc: %w", err)
	}
	return a, nil
}

// parseTOC streams the TOC XML token by token, collecting file entries
// (<toc><file>, nested) and signing certificates (<toc><signature> and
// <toc><x-signature>) without materialising the document.
func (a *Archive) parseTOC(r io.Reader) error {
	type frame struct {
		name  string
		entry int    // innermost enclosing file entry, or -1
		sig   int    // enclosing signature (0 signature, 1 x-signature), or -1
		rel   string // element path below that file or signature
	}
	var (
		stack   []frame
		parent  []int    // per entry: parent entry, or -1
		names   []string // per entry
		styles  [2]string
		certs   [2][]string
		text    strings.Builder
		rootEnd bool
	)
	d := xml.NewDecoder(r)
	for !rootEnd {
		tok, err := d.Token()
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		if err != nil {
			return err
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			if len(stack) >= maxTOCDepth {
				return errors.New("nested too deeply")
			}
			text.Reset()
			fr := frame{name: tok.Name.Local, entry: -1, sig: -1}
			if n := len(stack); n > 0 {
				top := stack[n-1]
				fr.entry, fr.sig = top.entry, top.sig
				fr.rel = path.Join(top.rel, fr.name)
				switch {
				case fr.name == "file" && (n == 2 && top.name == "toc" || top.entry >= 0 && top.rel == ""):
					if len(a.Entries) >= maxTOCEntries {
						return errors.New("too many entries")
					}
					a.Entries = append(a.Entries, Entry{})
					parent = append(parent, top.entry)
					names = append(names, "")
					fr.entry, fr.rel = len(a.Entries)-1, ""
				case n == 2 && top.name == "toc" && (fr.name == "signature" || fr.name == "x-signature"):
					fr.sig, fr.rel = 0, ""
					if fr.name == "x-signature" {
						fr.sig = 1
					}
					if styles[fr.sig] == "" {
						styles[fr.sig] = attr(tok, "style")
					}
				case fr.entry >= 0 && fr.rel == "data/encoding":
					a.Entries[fr.entry].Encoding = attr(tok, "style")
				}
			}
			stack = append(stack, fr)
		case xml.CharData:
			text.Write(tok)
		case xml.EndElement:
			n := len(stack)
			fr := stack[n-1]
			if fr.entry >= 0 && fr.rel != "" {
				e, s := &a.Entries[fr.entry], text.String()
				var err error
				switch fr.rel {
				case "name":
					names[fr.entry] = s
				case "type":
					e.Type = s
				case "link":
					e.Link = s
				case "data/offset":
					e.Offset, err = parseInt(s)
				case "data/length":
					e.Length, err = parseInt(s)
				case "data/size":
					e.Size, err = parseInt(s)
				}
				if err != nil {
					return err
				}
			}
			if fr.sig >= 0 && fr.rel == "KeyInfo/X509Data/X509Certificate" && len(certs[0])+len(certs[1]) < maxTOCCerts {
				certs[fr.sig] = append(certs[fr.sig], text.String())
			}
			text.Reset()
			stack = stack[:n-1]
			rootEnd = n == 1
		}
	}
	// Parents always precede their children, so one pass resolves paths.
	for i := range a.Entries {
		dir := ""
		if parent[i] >= 0 {
			dir = a.Entries[parent[i]].Path
		}
		a.Entries[i].Path = path.Join(dir, names[i])
	}
	for _, s := range styles {
		if a.SigStyle == "" {
			a.SigStyle = s
		}
	}
	for _, c := range append(certs[0], certs[1]...) {
		der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(c), ""))
		if err != nil {
			continue
		}
		if cert, err := x509.ParseCertificate(der); err == nil {
			a.Certs = append(a.Certs, cert)
		}
	}
	return nil
}

// parseInt reads an integer element, empty meaning 0 as with xml.Unmarshal.
func parseInt(s string) (int64, error) {
	if s = strings.TrimSpace(s); s == "" {
		return 0, nil
	}
	return strconv.ParseInt(s, 10, 64)
}

func attr(se xml.StartElement, name string) string {
	for _, a := range se.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func (a *Archive) Close() error { return a.f.Close() }

// Find returns the entry with the given path.
func (a *Archive) Find(p string) (Entry, bool) {
	for _, e := range a.Entries {
		if e.Path == p {
			return e, true
		}
	}
	return Entry{}, false
}

// Open returns the decoded contents of a file entry.
func (a *Archive) Open(e Entry) (io.ReadCloser, error) {
	sr := io.NewSectionReader(a.f, a.heap+e.Offset, e.Length)
	switch e.Encoding {
	case "application/x-gzip":
		// xar's "gzip" is actually zlib-wrapped deflate.
		zr, err := zlib.NewReader(sr)
		if err != nil {
			return nil, err
		}
		return zr, nil
	case "application/x-bzip2":
		return io.NopCloser(bzip2.NewReader(sr)), nil
	case "", "application/octet-stream":
		return io.NopCloser(sr), nil
	}
	return nil, fmt.Errorf("unsupported xar encoding %q", e.Encoding)
}

// ReadAll reads a (small) entry fully, up to max bytes.
func (a *Archive) ReadAll(e Entry, max int64) ([]byte, error) {
	rc, err := a.Open(e)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, max))
}

// PayloadReader decodes an installer Payload or Scripts stream, which is a
// cpio archive either raw, gzip-compressed, or pbzx (chunked xz).
func PayloadReader(r io.Reader) (io.Reader, error) {
	br := &peekReader{r: r}
	head, err := br.peek(6)
	if err != nil && len(head) < 4 {
		return nil, fmt.Errorf("payload: %w", err)
	}
	switch {
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		return gzip.NewReader(br)
	case bytes.HasPrefix(head, []byte("pbzx")):
		return newPBZX(br)
	case bytes.HasPrefix(head, []byte("0707")):
		return br, nil
	case bytes.HasPrefix(head, []byte("BZh")):
		return bzip2.NewReader(br), nil
	}
	return nil, fmt.Errorf("payload: unknown encoding % x", head)
}

type peekReader struct {
	r   io.Reader
	buf []byte
}

func (p *peekReader) peek(n int) ([]byte, error) {
	for len(p.buf) < n {
		b := make([]byte, n-len(p.buf))
		m, err := p.r.Read(b)
		p.buf = append(p.buf, b[:m]...)
		if err != nil {
			return p.buf, err
		}
	}
	return p.buf[:n], nil
}

func (p *peekReader) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.r.Read(b)
}
