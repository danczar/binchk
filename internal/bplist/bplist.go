// Package bplist reads and writes the small subset of Apple's binary
// property list format ("bplist00") binchk needs: arrays of strings. That
// covers kMDItemWhereFroms (download origin) and _kMDItemUserTags (Finder
// tags).
package bplist

import (
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

const (
	magic       = "bplist00"
	trailerSize = 32
	maxObjects  = 1 << 16
)

var ErrFormat = errors.New("bplist: malformed binary property list")

// EncodeStrings encodes ss as a binary property list holding one array of
// strings, the way CoreFoundation does: pure-ASCII strings use the ASCII
// form, anything else UTF-16BE.
func EncodeStrings(ss []string) []byte {
	numObj := 1 + len(ss)
	refSize := 1
	switch {
	case numObj > 0xffff:
		refSize = 4
	case numObj > 0xff:
		refSize = 2
	}
	b := []byte(magic)
	offsets := make([]int, 0, numObj)

	offsets = append(offsets, len(b))
	b = appendMarker(b, 0xA0, len(ss))
	for i := range ss {
		b = appendUint(b, uint64(i+1), refSize)
	}
	for _, s := range ss {
		offsets = append(offsets, len(b))
		if isASCII(s) {
			b = appendMarker(b, 0x50, len(s))
			b = append(b, s...)
			continue
		}
		u := utf16.Encode([]rune(s))
		b = appendMarker(b, 0x60, len(u))
		for _, c := range u {
			b = binary.BigEndian.AppendUint16(b, c)
		}
	}
	tableOff := len(b)
	offSize := uintSize(uint64(tableOff))
	for _, o := range offsets {
		b = appendUint(b, uint64(o), offSize)
	}
	var tr [trailerSize]byte
	tr[6] = byte(offSize)
	tr[7] = byte(refSize)
	binary.BigEndian.PutUint64(tr[8:], uint64(numObj))
	binary.BigEndian.PutUint64(tr[16:], 0) // top object
	binary.BigEndian.PutUint64(tr[24:], uint64(tableOff))
	return append(b, tr[:]...)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// appendMarker writes an object marker with its count, using the extended
// int-object form for counts of 15 and more.
func appendMarker(b []byte, kind byte, n int) []byte {
	if n < 15 {
		return append(b, kind|byte(n))
	}
	b = append(b, kind|0x0f)
	switch w := uintSize(uint64(n)); w {
	case 1:
		b = append(b, 0x10)
	case 2:
		b = append(b, 0x11)
	case 4:
		b = append(b, 0x12)
	default:
		b = append(b, 0x13)
	}
	return appendUint(b, uint64(n), uintSize(uint64(n)))
}

func uintSize(v uint64) int {
	switch {
	case v <= 0xff:
		return 1
	case v <= 0xffff:
		return 2
	case v <= 0xffffffff:
		return 4
	}
	return 8
}

func appendUint(b []byte, v uint64, w int) []byte {
	for i := w - 1; i >= 0; i-- {
		b = append(b, byte(v>>(8*i)))
	}
	return b
}

type doc struct {
	b                 []byte
	offSize, refSize  int
	numObj, top, tOff uint64
}

func parse(b []byte) (*doc, error) {
	if len(b) < len(magic)+trailerSize || string(b[:len(magic)]) != magic {
		return nil, ErrFormat
	}
	tr := b[len(b)-trailerSize:]
	d := &doc{
		b: b, offSize: int(tr[6]), refSize: int(tr[7]),
		numObj: binary.BigEndian.Uint64(tr[8:]), top: binary.BigEndian.Uint64(tr[16:]),
		tOff: binary.BigEndian.Uint64(tr[24:]),
	}
	end := uint64(len(b) - trailerSize)
	if d.offSize < 1 || d.offSize > 8 || d.refSize < 1 || d.refSize > 8 || d.numObj == 0 || d.numObj > maxObjects ||
		d.top >= d.numObj || d.tOff > end || d.numObj*uint64(d.offSize) > end-d.tOff {
		return nil, ErrFormat
	}
	return d, nil
}

func readUint(p []byte) uint64 {
	var v uint64
	for _, c := range p {
		v = v<<8 | uint64(c)
	}
	return v
}

// offset returns where object i starts.
func (d *doc) offset(i uint64) (uint64, bool) {
	if i >= d.numObj {
		return 0, false
	}
	p := d.tOff + i*uint64(d.offSize)
	off := readUint(d.b[p : p+uint64(d.offSize)])
	return off, off >= uint64(len(magic)) && off < d.tOff
}

// header decodes the marker at off: its kind nibble, element count and the
// position of its payload.
func (d *doc) header(off uint64) (kind byte, n, start uint64, ok bool) {
	marker := d.b[off]
	kind, n, start = marker>>4, uint64(marker&0x0f), off+1
	if n != 0x0f || kind == 0 || kind == 1 || kind == 2 || kind == 3 {
		return kind, n, start, true
	}
	if start >= d.tOff || d.b[start]>>4 != 1 {
		return 0, 0, 0, false
	}
	w := uint64(1) << (d.b[start] & 0x0f)
	if w > 8 || start+1+w > d.tOff {
		return 0, 0, 0, false
	}
	return kind, readUint(d.b[start+1 : start+1+w]), start + 1 + w, true
}

// str decodes object i if it is a string.
func (d *doc) str(i uint64) (string, bool) {
	off, ok := d.offset(i)
	if !ok {
		return "", false
	}
	kind, n, start, ok := d.header(off)
	if !ok {
		return "", false
	}
	switch kind {
	case 5:
		if n > d.tOff-start {
			return "", false
		}
		return string(d.b[start : start+n]), true
	case 6:
		if n > (d.tOff-start)/2 {
			return "", false
		}
		u := make([]uint16, n)
		for k := range u {
			u[k] = binary.BigEndian.Uint16(d.b[start+2*uint64(k):])
		}
		return string(utf16.Decode(u)), true
	}
	return "", false
}

// DecodeStrings decodes a property list whose top object is an array of
// strings. Anything else is an error, so a caller never rewrites data it did
// not understand.
func DecodeStrings(b []byte) ([]string, error) {
	d, err := parse(b)
	if err != nil {
		return nil, err
	}
	off, ok := d.offset(d.top)
	if !ok {
		return nil, ErrFormat
	}
	kind, n, start, ok := d.header(off)
	if !ok || kind != 0xA || n > d.numObj || n*uint64(d.refSize) > d.tOff-start {
		return nil, ErrFormat
	}
	out := make([]string, 0, n)
	for k := uint64(0); k < n; k++ {
		p := start + k*uint64(d.refSize)
		s, ok := d.str(readUint(d.b[p : p+uint64(d.refSize)]))
		if !ok {
			return nil, ErrFormat
		}
		out = append(out, s)
	}
	return out, nil
}

// Strings returns every string object in a binary property list, in object
// order, skipping anything it cannot decode. It never fails: malformed input
// yields nil.
func Strings(b []byte) []string {
	d, err := parse(b)
	if err != nil {
		return nil
	}
	var out []string
	for i := uint64(0); i < d.numObj; i++ {
		if s, ok := d.str(i); ok {
			out = append(out, s)
		}
	}
	return out
}
