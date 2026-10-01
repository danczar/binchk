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
	// Any version is accepted; fork ranges must lie inside the file.
	koly := func(version uint32, dataOff, dataLen uint64) []byte {
		b := append([]byte{}, dmg...)
		k := b[len(b)-512:]
		binary.BigEndian.PutUint32(k[4:], version)
		binary.BigEndian.PutUint64(k[0x18:], dataOff)
		binary.BigEndian.PutUint64(k[0x20:], dataLen)
		return b
	}
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
		{"koly fork past trailer", koly(4, 0, 3585), Unknown},
		{"koly fork offset overflow", koly(4, 1<<63, 1<<63), Unknown},
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
