package bplist

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var cases = [][]string{
	{},
	{"Red\n6"},
	{"Work", "binchk: Suspicious\n7", "Rød\n2", "日本語", "emoji 🙂 tag\n4"},
	{strings.Repeat("a", 14), strings.Repeat("b", 15), strings.Repeat("c", 255), strings.Repeat("d", 256), strings.Repeat("é", 70000)},
	manyStrings(300), // two-byte object references
}

func manyStrings(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("tag %d", i)
	}
	return out
}

func TestRoundTrip(t *testing.T) {
	for _, want := range cases {
		b := EncodeStrings(want)
		got, err := DecodeStrings(b)
		if err != nil {
			t.Fatalf("%d strings: %v", len(want), err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("round trip: got %q want %q", got, want)
		}
		if all := Strings(b); len(want) > 0 && !reflect.DeepEqual(all, want) {
			t.Fatalf("Strings: got %d strings", len(all))
		}
	}
}

// handBuilt encodes an array of short ASCII strings the way the old
// provenance tests did, independently of EncodeStrings.
func handBuilt(strs ...string) []byte {
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
	tr[15] = byte(len(offs))
	tr[31] = byte(table)
	return append(b, tr...)
}

func TestDecodeHandBuilt(t *testing.T) {
	want := []string{"https://example.com/downloads/tool.dmg", "https://x.io/"}
	b := handBuilt(want...)
	if got := Strings(b); !reflect.DeepEqual(got, want) {
		t.Fatalf("Strings: got %q want %q", got, want)
	}
	if got, err := DecodeStrings(b); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("DecodeStrings: got %q %v", got, err)
	}
}

func TestMalformed(t *testing.T) {
	good := EncodeStrings([]string{"one", "two"})
	inputs := [][]byte{
		nil,
		[]byte("garbage"),
		[]byte("bplist00"),
		good[:len(good)-1],
		append([]byte("bplist01"), good[8:]...),
	}
	// Corrupt every byte in turn: decoding must never panic.
	for i := range good {
		c := append([]byte{}, good...)
		c[i] ^= 0xff
		inputs = append(inputs, c)
	}
	for _, in := range inputs[:5] {
		if _, err := DecodeStrings(in); err == nil {
			t.Errorf("DecodeStrings(%q) succeeded", in)
		}
		if Strings(in) != nil {
			t.Errorf("Strings(%q) returned data", in)
		}
	}
	for _, in := range inputs[5:] {
		DecodeStrings(in)
		Strings(in)
	}
	// A dictionary at the top is not an array of strings.
	dict := []byte("bplist00\xd0\x08\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09")
	if _, err := DecodeStrings(dict); err == nil {
		t.Error("dictionary decoded as a string array")
	}
}

// plutil, where available, must read what we write and we must read what it
// writes.
func TestPlutilInterop(t *testing.T) {
	plutil, err := exec.LookPath("plutil")
	if err != nil {
		t.Skip("plutil not available")
	}
	dir := t.TempDir()
	for i, want := range cases {
		p := filepath.Join(dir, fmt.Sprintf("ours%d.plist", i))
		if err := os.WriteFile(p, EncodeStrings(want), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(plutil, "-convert", "json", "-o", "-", p).Output()
		if err != nil {
			t.Fatalf("plutil rejected our plist %d: %v", i, err)
		}
		var got []string
		if err := json.Unmarshal(out, &got); err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("plutil read %d: %v (%d strings)", i, err, len(got))
		}

		js, _ := json.Marshal(want)
		q := filepath.Join(dir, fmt.Sprintf("theirs%d.plist", i))
		os.WriteFile(q, js, 0o644)
		if out, err := exec.Command(plutil, "-convert", "binary1", q).CombinedOutput(); err != nil {
			t.Fatalf("plutil convert: %v %s", err, out)
		}
		b, _ := os.ReadFile(q)
		if got, err := DecodeStrings(b); err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("reading plutil's plist %d: %v (%d strings)", i, err, len(got))
		}
	}
}
