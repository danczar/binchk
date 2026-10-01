package detect

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

func TestSniff(t *testing.T) {
	pe := make([]byte, 0x100)
	copy(pe, "MZ")
	binary.LittleEndian.PutUint32(pe[0x3c:], 0x80)
	copy(pe[0x80:], "PE\x00\x00")
	mzOnly := append([]byte{}, pe...)
	copy(mzOnly[0x80:], "XX")

	dmg := make([]byte, 4096)
	copy(dmg[len(dmg)-512:], "koly\x00\x00\x00\x04\x00\x00\x02\x00")
	bareKoly := make([]byte, 4096)
	copy(bareKoly[len(bareKoly)-512:], "koly")
	// Only what hdiutil needs is checked: the signature, a version and an
	// XML plist range inside the file. hdiutil mounts images whose header
	// size is 0 or 0x400 or whose data fork length runs past the file.
	koly := func(version uint32, dataOff, dataLen uint64) []byte {
		b := append([]byte{}, dmg...)
		k := b[len(b)-512:]
		binary.BigEndian.PutUint32(k[4:], version)
		binary.BigEndian.PutUint64(k[0x18:], dataOff)
		binary.BigEndian.PutUint64(k[0x20:], dataLen)
		return b
	}
	field := func(at, width int, v uint64) []byte {
		b := append([]byte{}, dmg...)
		k := b[len(b)-512:]
		if width == 4 {
			binary.BigEndian.PutUint32(k[at:], uint32(v))
		} else {
			binary.BigEndian.PutUint64(k[at:], v)
		}
		return b
	}
	xml := func(off, n uint64) []byte {
		b := field(0xD8, 8, off)
		binary.BigEndian.PutUint64(b[len(b)-512+0xE0:], n)
		return b
	}
	// hdiutil also accepts the header at the start of the file, with its
	// offsets counted from there.
	front := append(append([]byte{}, dmg[len(dmg)-512:]...), make([]byte, 3584)...)
	binary.BigEndian.PutUint64(front[0xD8:], 1024)
	binary.BigEndian.PutUint64(front[0xE0:], 100)
	// Executables with a valid UDIF trailer appended still run: the
	// leading magic must win.
	withTrailer := func(b []byte) []byte {
		out := append(append([]byte{}, b...), make([]byte, 1024)...)
		copy(out[len(out)-512:], dmg[len(dmg)-512:])
		return out
	}

	cases := []struct {
		name string
		data []byte
		want Format
	}{
		{"elf", []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"), ELF},
		{"macho64", []byte{0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1}, MachO},
		{"fat", []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2}, MachOFat},
		{"java class", []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x3d}, Unknown},
		{"pe", pe, PE},
		{"dos stub only", mzOnly, Unknown},
		{"text", []byte("#!/bin/sh\necho hi\n"), Unknown},
		{"empty", nil, Unknown},
		{"dmg", dmg, DiskImage},
		{"bare koly signature", bareKoly, Unknown},
		{"dmg v3", koly(3, 0, 3584), DiskImage},
		{"koly version 0", koly(0, 0, 0), Unknown},
		{"koly fork past trailer", koly(4, 0, 3585), DiskImage},
		{"koly fork length 0xffffffffffff", koly(4, 0, 0xffffffffffff), DiskImage},
		{"koly fork offset overflow", koly(4, 1<<63, 1<<63), DiskImage},
		{"koly header size 0", field(8, 4, 0), DiskImage},
		{"koly header size 0x400", field(8, 4, 0x400), DiskImage},
		{"koly xml into trailer", xml(3000, 1096), DiskImage},
		{"koly xml past eof", xml(3000, 1097), Unknown},
		{"koly xml offset past eof", xml(4097, 0), Unknown},
		{"koly xml overflow", xml(1<<63, 1<<63), Unknown},
		{"koly header at start", front, DiskImage},
		{"koly header at start, version 0", append([]byte("koly\x00\x00\x00\x00"), make([]byte, 4088)...), Unknown},
		{"elf+koly", withTrailer([]byte("\x7fELF\x02\x01\x01\x00")), ELF},
		{"macho+koly", withTrailer([]byte{0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1}), MachO},
		{"fat+koly", withTrailer([]byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2}), MachOFat},
		{"pe+koly", withTrailer(pe), PE},
		{"encrypted dmg", []byte("encrcdsa\x00\x00\x00\x02"), DiskImage},
		{"pkg", []byte("xar!\x00\x1c\x00\x01"), InstallerPkg},
	}
	for _, c := range cases {
		if got := Sniff(bytes.NewReader(c.data), int64(len(c.data))); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestSniffPathBundle(t *testing.T) {
	d := t.TempDir()
	app := d + "/Foo.app"
	os.MkdirAll(app+"/Contents/MacOS", 0o755)
	if SniffPath(app) != AppBundle {
		t.Error("bundle not recognised")
	}
	os.MkdirAll(d+"/Bar.app", 0o755) // no Contents: just a folder
	if SniffPath(d+"/Bar.app") != Unknown {
		t.Error("empty .app folder recognised as bundle")
	}
}

func TestUDIFPolyglot(t *testing.T) {
	trailer := func(lead []byte, dataOff uint64) []byte {
		b := make([]byte, 4096)
		copy(b, lead)
		k := b[len(b)-512:]
		copy(k, "koly\x00\x00\x00\x04\x00\x00\x02\x00")
		binary.BigEndian.PutUint64(k[0x18:], dataOff)
		return b
	}
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"plain image", trailer([]byte{0x78, 0xda, 1, 2}, 0), false},
		{"no trailer", []byte("#!/bin/sh\necho hi\n"), false},
		{"script", trailer([]byte("#!/bin/sh\n"), 0), true},
		{"macho", trailer([]byte{0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1}, 0), true},
		{"xar", trailer([]byte("xar!\x00\x1c\x00\x01"), 0), true},
		{"encrcdsa", trailer([]byte("encrcdsa\x00\x00\x00\x02"), 0), true},
		{"bytes before data fork", trailer(nil, 1024), true},
		{"bom script", trailer([]byte("\xef\xbb\xbf#!/bin/sh\n"), 0), true},
		{"header size 0", func() []byte {
			b := trailer([]byte{0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1}, 0)
			binary.BigEndian.PutUint32(b[len(b)-512+8:], 0)
			return b
		}(), true},
	}
	for _, c := range cases {
		if got := UDIFPolyglot(bytes.NewReader(c.data), int64(len(c.data))); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	// A script with a trailer still sniffs as an image so it is picked up.
	s := trailer([]byte("#!/bin/sh\n"), 0)
	if f := Sniff(bytes.NewReader(s), int64(len(s))); f != DiskImage {
		t.Errorf("script+koly sniffed as %q", f)
	}
}
