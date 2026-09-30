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

type tocFile struct {
	Name string `xml:"name"`
	Type string `xml:"type"`
	Link string `xml:"link"`
	Data *struct {
		Offset   int64 `xml:"offset"`
		Length   int64 `xml:"length"`
		Size     int64 `xml:"size"`
		Encoding struct {
			Style string `xml:"style,attr"`
		} `xml:"encoding"`
	} `xml:"data"`
	Files []tocFile `xml:"file"`
}

type tocSig struct {
	Style string   `xml:"style,attr"`
	Certs []string `xml:"KeyInfo>X509Data>X509Certificate"`
}

type toc struct {
	Files     []tocFile `xml:"toc>file"`
	Signature []tocSig  `xml:"toc>signature"`
	XSig      []tocSig  `xml:"toc>x-signature"`
}

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
	if h.TOCCompLen > 64<<20 || h.TOCUncompLn > 256<<20 {
		f.Close()
		return nil, errors.New("xar table of contents too large")
	}
	zr, err := zlib.NewReader(io.NewSectionReader(f, int64(h.HeaderSize), int64(h.TOCCompLen)))
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("xar toc: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(zr, int64(h.TOCUncompLn)+1))
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("xar toc: %w", err)
	}
	var t toc
	if err := xml.Unmarshal(raw, &t); err != nil {
		f.Close()
		return nil, fmt.Errorf("xar toc: %w", err)
	}
	a := &Archive{f: f, heap: int64(h.HeaderSize) + int64(h.TOCCompLen)}
	var walk func(prefix string, fs []tocFile)
	walk = func(prefix string, fs []tocFile) {
		for _, tf := range fs {
			p := path.Join(prefix, tf.Name)
			e := Entry{Path: p, Type: tf.Type, Link: tf.Link}
			if tf.Data != nil {
				e.Offset, e.Length, e.Size, e.Encoding = tf.Data.Offset, tf.Data.Length, tf.Data.Size, tf.Data.Encoding.Style
			}
			a.Entries = append(a.Entries, e)
			walk(p, tf.Files)
		}
	}
	walk("", t.Files)
	for _, s := range append(t.Signature, t.XSig...) {
		if a.SigStyle == "" {
			a.SigStyle = s.Style
		}
		for _, c := range s.Certs {
			der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(c), ""))
			if err != nil {
				continue
			}
			if cert, err := x509.ParseCertificate(der); err == nil {
				a.Certs = append(a.Certs, cert)
			}
		}
	}
	return a, nil
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
