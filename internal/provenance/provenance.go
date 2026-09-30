// Package provenance reads where a downloaded file came from, using the
// metadata browsers attach: com.apple.quarantine / kMDItemWhereFroms on
// macOS, user.xdg.origin.url on Linux, the Zone.Identifier stream on Windows.
package provenance

import (
	"encoding/binary"
	"unicode/utf16"

	"github.com/danczar/binchk/internal/analyze"
)

// Read never fails; missing metadata just yields an empty Provenance.
func Read(path string) analyze.Provenance { return read(path) }

// bplistStrings returns every string object in a binary property list, in
// object order. kMDItemWhereFroms is an array of [url, referrer], so this is
// all we need without a general plist decoder.
func bplistStrings(b []byte) []string {
	if len(b) < 40 || string(b[:8]) != "bplist00" {
		return nil
	}
	tr := b[len(b)-32:]
	offSize := int(tr[6])
	numObj := binary.BigEndian.Uint64(tr[8:])
	tableOff := binary.BigEndian.Uint64(tr[24:])
	if offSize < 1 || offSize > 8 || numObj > 1024 || tableOff+numObj*uint64(offSize) > uint64(len(b)) {
		return nil
	}
	readUint := func(p []byte) uint64 {
		var v uint64
		for _, c := range p {
			v = v<<8 | uint64(c)
		}
		return v
	}
	var out []string
	for i := uint64(0); i < numObj; i++ {
		p := tableOff + i*uint64(offSize)
		off := readUint(b[p : p+uint64(offSize)])
		if off >= uint64(len(b)) {
			continue
		}
		marker := b[off]
		kind, n := marker>>4, uint64(marker&0x0f)
		if kind != 5 && kind != 6 {
			continue
		}
		start := off + 1
		if n == 0x0f { // length follows as an int object
			if start >= uint64(len(b)) || b[start]>>4 != 1 {
				continue
			}
			w := uint64(1) << (b[start] & 0x0f)
			if start+1+w > uint64(len(b)) || w > 8 {
				continue
			}
			n = readUint(b[start+1 : start+1+w])
			start += 1 + w
		}
		if kind == 5 {
			if start+n <= uint64(len(b)) {
				out = append(out, string(b[start:start+n]))
			}
			continue
		}
		if start+2*n <= uint64(len(b)) {
			u := make([]uint16, n)
			for k := range u {
				u[k] = binary.BigEndian.Uint16(b[start+2*uint64(k):])
			}
			out = append(out, string(utf16.Decode(u)))
		}
	}
	return out
}
