package app

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A shell may pass an NFC name for a file stored as NFD (APFS matches
// either). Quick Look asks with the stored spelling, so the pointer must be
// recorded under it too, or the preview falls back to the content map.
func TestPointerUnderListedSpelling(t *testing.T) {
	h := newHarness(t, nil)
	dir := filepath.Join(h.root, "files")
	os.MkdirAll(dir, 0o755)
	nfd := filepath.Join(dir, "café")
	nfc := filepath.Join(dir, "café")
	if err := os.WriteFile(nfd, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(nfc); err != nil {
		t.Skip("file system does not match names regardless of normalization")
	}
	e := h.analyse(t, nfc)
	for _, p := range []string{nfc, nfd} {
		ptr, err := h.Index().Pointer(p)
		if err != nil || ptr.Entry != e.EntryID {
			t.Errorf("no pointer for %q: %+v %v", p, ptr, err)
		}
		if !slices.Contains(e.Paths, p) {
			t.Errorf("entry paths %q lack %q", e.Paths, p)
		}
	}
	// A hard link under another name is a different item, not a spelling.
	other := filepath.Join(dir, "naïve")
	if err := os.Link(nfd, other); err != nil {
		t.Fatal(err)
	}
	if got := listedNames(nfd); len(got) != 0 {
		t.Errorf("hard link taken for a spelling: %q", got)
	}
	// ASCII names are never looked up.
	if got := listedNames(filepath.Join(dir, "plain")); got != nil {
		t.Errorf("ascii: %q", got)
	}
}
