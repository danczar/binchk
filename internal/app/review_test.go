package app

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/danczar/binchk/internal/config"
	"github.com/danczar/binchk/internal/container"
	"github.com/danczar/binchk/internal/findertag"
	"github.com/danczar/binchk/internal/index"
)

// These tests reproduce the index-identity flaws found in review: items
// that share content (or only a main executable) must never share a card,
// and Mark as safe must neither leak to a different bundle nor leave copies
// tagged.

func fileSHA(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

const toolPlist = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>%s</string>
<key>CFBundleIdentifier</key><string>com.example.tool</string>
</dict></plist>`

// makeBundle builds dir/name.app with main executable exe (a copy of
// mainSrc) and extra files copied in at their bundle-relative paths.
func makeBundle(t *testing.T, dir, name, exe, mainSrc string, extra map[string]string) string {
	t.Helper()
	app := filepath.Join(dir, name+".app")
	if err := os.MkdirAll(filepath.Join(app, "Contents/MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents/Info.plist"), fmt.Appendf(nil, toolPlist, exe), 0o644); err != nil {
		t.Fatal(err)
	}
	if mainSrc != "" {
		copyFile(t, mainSrc, filepath.Join(app, "Contents/MacOS", filepath.Base(exe)))
	}
	for rel, src := range extra {
		os.MkdirAll(filepath.Dir(filepath.Join(app, rel)), 0o755)
		copyFile(t, src, filepath.Join(app, rel))
	}
	return app
}

// analyse runs the watch pipeline on path synchronously.
func (h *harness) analyse(t *testing.T, path string) *index.Entry {
	t.Helper()
	h.Handle(path, time.Now())
	e := h.Latest()
	if e == nil || e.Path != path {
		t.Fatalf("no result for %s: %+v", path, e)
	}
	return e
}

// bundleHarness is a harness whose blocklist holds payload's hash.
func bundleHarness(t *testing.T, payload string, allow ...string) *harness {
	t.Helper()
	return newHarness(t, func(cfg *config.Config) {
		bl := filepath.Join(filepath.Dir(cfg.DataDir), "blocklist.txt")
		os.WriteFile(bl, []byte(fileSHA(t, payload)+" test payload\n"), 0o644)
		cfg.BlocklistFile = bl
		var al strings.Builder
		for _, p := range allow {
			al.WriteString(fileSHA(t, p) + " allowed\n")
		}
		os.WriteFile(cfg.AllowlistFile, []byte(al.String()), 0o644)
	})
}

// cardFor is the card a reader finds for path through its pointer.
func cardFor(t *testing.T, x *index.Index, path string) string {
	t.Helper()
	p, err := x.Pointer(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(x.CardPath(p.Entry))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func markSafe(t *testing.T, h *harness, e *index.Entry) {
	t.Helper()
	if err := h.MarkSafe(e.EntryID); err != nil {
		t.Fatal(err)
	}
}

func mainExe(app string) (string, bool) { return container.MainExecutable(app) }

func payloadFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "payload")
	copyFile(t, "/bin/cat", p)
	return p
}

// Benign.app and Trojan.app share their main executable; Trojan.app adds a
// blocklisted framework. Each keeps its own card, whichever is analysed last.
func TestReviewBundlesShareMainExecutable(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("app bundles are handled on macOS")
	}
	payload := payloadFile(t)
	h := bundleHarness(t, payload)
	dir := filepath.Join(h.root, "apps")
	benign := makeBundle(t, dir, "Benign", "Tool", "/bin/echo", nil)
	trojan := makeBundle(t, dir, "Trojan", "Tool", "/bin/echo", map[string]string{"Contents/Frameworks/libpayload.dylib": payload})

	te := h.analyse(t, trojan)
	if te.Verdict != "Malicious" {
		t.Fatalf("trojan: %s %s", te.Verdict, te.Summary)
	}
	be := h.analyse(t, benign)
	if be.Verdict == "Malicious" {
		t.Fatalf("benign: %s %s", be.Verdict, be.Summary)
	}
	tc := cardFor(t, h.Index(), trojan)
	if !strings.Contains(tc, "<h1>Trojan.app</h1>") || !strings.Contains(tc, "Malicious") {
		t.Fatalf("Trojan.app shows another item's card:\n%s", tc)
	}
	if bc := cardFor(t, h.Index(), benign); !strings.Contains(bc, "<h1>Benign.app</h1>") || strings.Contains(bc, "pill\">Malicious") {
		t.Fatalf("Benign.app card:\n%s", bc)
	}

	// Marking the benign app safe trusts that bundle only: the trojanized
	// sibling, which reuses its main executable, stays Malicious.
	markSafe(t, h, be)
	if again := h.analyse(t, trojan); again.Verdict != "Malicious" || again.MarkedSafe {
		t.Fatalf("trojan after marking its sibling safe: %s %d %s", again.Verdict, again.Score, again.Summary)
	}
	if again := h.analyse(t, benign); again.Verdict != "Clean" || !again.MarkedSafe {
		t.Fatalf("benign after marking it safe: %+v", again)
	}
}

// Identical bytes under different names are different items: name-based
// findings change the verdict, so each keeps its own card.
func TestReviewIdenticalFilesDifferentNames(t *testing.T) {
	benign := buildSample(t, "benign")
	h := newHarness(t, nil)
	dir := filepath.Join(h.root, "files")
	os.MkdirAll(dir, 0o755)
	plain := filepath.Join(dir, "hello")
	double := filepath.Join(dir, "hello.pdf.exe")
	copyFile(t, benign, plain)
	copyFile(t, benign, double)

	de := h.analyse(t, double)
	if de.Verdict == "Clean" {
		t.Fatalf("double extension: %s %s", de.Verdict, de.Summary)
	}
	pe := h.analyse(t, plain)
	if pe.Verdict != "Clean" {
		t.Fatalf("plain: %s %s", pe.Verdict, pe.Summary)
	}
	dc := cardFor(t, h.Index(), double)
	if !strings.Contains(dc, "<h1>hello.pdf.exe</h1>") || !strings.Contains(dc, "Double file extension") {
		t.Fatalf("hello.pdf.exe shows another item's card:\n%s", dc)
	}
	if pc := cardFor(t, h.Index(), plain); !strings.Contains(pc, "<h1>hello</h1>") || !strings.Contains(pc, "pill\">Clean") {
		t.Fatalf("hello card:\n%s", pc)
	}
	// Recent reports list both analyses, not one per content.
	if r := h.Recent(); len(r) != 2 || r[0].Path != plain || r[1].Path != double || r[0].ContentKey != r[1].ContentKey {
		t.Fatalf("recent %+v", r)
	}
	a2, err := New(h.cfg, false, "test")
	if err != nil {
		t.Fatal(err)
	}
	if r := a2.Recent(); len(r) != 2 {
		t.Fatalf("recent after restart %+v", r)
	}
}

// Mark as safe removes binchk's tag from every copy of the content, not
// only the most recently analysed one.
func TestReviewMarkSafeUntagsAllCopies(t *testing.T) {
	if !findertag.Supported() {
		t.Skip("Finder tags are macOS only")
	}
	evil := buildSample(t, "evil")
	h := newHarness(t, nil)
	dir := filepath.Join(h.root, "copies")
	os.MkdirAll(dir, 0o755)
	var paths []string
	var first *index.Entry
	for _, n := range []string{"ro-bin", "tmpbin", "oldbin"} {
		p := filepath.Join(dir, n)
		copyFile(t, evil, p)
		e := h.analyse(t, p)
		if first == nil {
			first = e
		}
		if got := tags(t, p); len(got) != 1 {
			t.Fatalf("%s tags %q", p, got)
		}
		paths = append(paths, p)
	}
	// A copy that changed since its analysis keeps its tag.
	changed := filepath.Join(dir, "changed")
	copyFile(t, evil, changed)
	h.analyse(t, changed)
	b, _ := os.ReadFile(changed)
	os.WriteFile(changed, append(b, 'x'), 0o755)

	markSafe(t, h, first)
	for _, p := range paths {
		if got := tags(t, p); len(got) != 0 {
			t.Errorf("%s still tagged %q after mark as safe", p, got)
		}
	}
	if got := tags(t, changed); len(got) != 1 {
		t.Errorf("changed copy lost its tag: %q", got)
	}
}

// A CFBundleExecutable that leaves the bundle is not an identity: the
// bundle cannot borrow an allowlisted file outside it.
func TestReviewEscapingExecutable(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("app bundles are handled on macOS")
	}
	benign := buildSample(t, "benign")
	payload := payloadFile(t)
	root := t.TempDir()
	outside := filepath.Join(root, "benign-outside")
	copyFile(t, benign, outside)
	h := bundleHarness(t, payload, outside)
	app := makeBundle(t, root, "E", "../../../benign-outside", "", map[string]string{"Contents/MacOS/E": payload})
	if p, ok := mainExe(app); ok {
		t.Errorf("escaping CFBundleExecutable accepted: %s", p)
	}
	e := h.analyse(t, app)
	if e.Verdict != "Malicious" {
		t.Fatalf("bundle borrowed an outside identity: %s %d %s", e.Verdict, e.Score, e.Summary)
	}
}

// A trojanized copy that keeps the main executable and the seal and swaps a
// nested library for a payload of exactly the same size has the same bundle
// fingerprint (which records sizes only). Trusting the clean app must still
// not trust it: the allowlist keys a bundle by its full contents.
func TestReviewSameSizePayloadNotTrusted(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("app bundles are handled on macOS")
	}
	payload := payloadFile(t)
	h := bundleHarness(t, payload)
	b, err := os.ReadFile(payload)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 0xff
	benignLib := filepath.Join(t.TempDir(), "libx.dylib")
	if err := os.WriteFile(benignLib, b, 0o755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(h.root, "apps")
	benign := makeBundle(t, dir, "Benign", "Tool", "/bin/echo", map[string]string{"Contents/Frameworks/libx.dylib": benignLib})
	trojan := makeBundle(t, dir, "Trojan", "Tool", "/bin/echo", map[string]string{"Contents/Frameworks/libx.dylib": payload})
	copied := makeBundle(t, filepath.Join(h.root, "copy"), "Benign", "Tool", "/bin/echo", map[string]string{"Contents/Frameworks/libx.dylib": benignLib})

	ce := h.analyse(t, copied)
	be := h.analyse(t, benign)
	te := h.analyse(t, trojan)
	if te.Verdict != "Malicious" {
		t.Fatalf("trojan: %s %d %s", te.Verdict, te.Score, te.Summary)
	}
	if be.ContentKey != te.ContentKey {
		t.Fatalf("fingerprints differ (%s, %s): the test no longer reproduces the collision", be.ContentKey, te.ContentKey)
	}
	if be.TrustKey == te.TrustKey || !index.IsDigest(be.TrustKey) {
		t.Fatalf("benign and trojan trust keys %q %q", be.TrustKey, te.TrustKey)
	}
	tagged := findertag.Supported() && len(tags(t, trojan)) == 1
	markSafe(t, h, be)
	if got, err := h.Index().Get(te.EntryID); err != nil || got.MarkedSafe {
		t.Fatalf("trojan's entry marked safe with its sibling: %+v %v", got, err)
	}
	// An identical copy elsewhere is the same contents, and is marked too.
	if ce.TrustKey != be.TrustKey {
		t.Fatalf("identical copies have different trust keys")
	}
	if got, err := h.Index().Get(ce.EntryID); err != nil || !got.MarkedSafe {
		t.Fatalf("identical copy not marked safe: %+v %v", got, err)
	}
	if tagged {
		if got := tags(t, trojan); len(got) != 1 {
			t.Errorf("trojan lost its tag: %q", got)
		}
	}
	again := h.analyse(t, trojan)
	if again.Verdict != "Malicious" || again.MarkedSafe {
		t.Fatalf("trojan after marking its same-size sibling safe: %s %d %s", again.Verdict, again.Score, again.Summary)
	}
	if again := h.analyse(t, benign); again.Verdict != "Clean" || !again.MarkedSafe {
		t.Fatalf("benign after marking it safe: %+v", again)
	}
}
