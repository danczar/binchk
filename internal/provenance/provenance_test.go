package provenance

import (
	"encoding/binary"
	"reflect"
	"testing"
)

// buildBplist encodes an array of ASCII strings as a binary plist.
func buildBplist(strs ...string) []byte {
	b := []byte("bplist00")
	var offs []int
	offs = append(offs, len(b))
	b = append(b, 0xA0|byte(len(strs)))
	for i := range strs {
		b = append(b, byte(i+1))
	}
	for _, s := range strs {
		offs = append(offs, len(b))
		if len(s) < 15 {
			b = append(b, 0x50|byte(len(s)))
		} else {
			b = append(b, 0x5F, 0x10, byte(len(s)))
		}
		b = append(b, s...)
	}
	table := len(b)
	for _, o := range offs {
		b = append(b, byte(o))
	}
	tr := make([]byte, 32)
	tr[6], tr[7] = 1, 1
	binary.BigEndian.PutUint64(tr[8:], uint64(len(offs)))
	binary.BigEndian.PutUint64(tr[24:], uint64(table))
	return append(b, tr...)
}

func TestBplistStrings(t *testing.T) {
	want := []string{"https://example.com/downloads/tool.dmg", "https://x.io/"}
	if got := bplistStrings(buildBplist(want...)); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
	if bplistStrings([]byte("garbage")) != nil {
		t.Fatal("garbage should yield nil")
	}
}
