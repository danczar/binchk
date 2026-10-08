package app

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/danczar/binchk/internal/notify"
)

// TestQuickLookJoin joins the two halves of the index contract: binchk
// (`binchk scan` and the watch pipeline) writes a scratch index, and the
// compiled Swift reader the Quick Look extension uses resolves items
// against it. It needs swiftc, so it is opt-in: BINCHK_QL_JOIN=1, which
// `make quicklook-join` sets.
func TestQuickLookJoin(t *testing.T) {
	if os.Getenv("BINCHK_QL_JOIN") == "" {
		t.Skip("set BINCHK_QL_JOIN=1 (make quicklook-join) to run")
	}
	bin := t.TempDir()
	binchk := filepath.Join(bin, "binchk")
	cmd := exec.Command("go", "build", "-o", binchk, "../../cmd/binchk")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	lookupBin := filepath.Join(bin, "lookup")
	arch := map[string]string{"arm64": "arm64", "amd64": "x86_64"}[runtime.GOARCH]
	cmd = exec.Command("swiftc", "-swift-version", "6", "-target", arch+"-apple-macos13.0", "-o", lookupBin,
		"../../macos/QuickLook/Sources/Core/BinchkIndex.swift", "../../macos/QuickLook/Tests/Lookup/main.swift")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("swiftc: %v\n%s", err, out)
	}

	payload := payloadFile(t)
	benignSample := buildSample(t, "benign")
	evilSample := buildSample(t, "evil")
	root := t.TempDir()
	cfg := testConfig(root)
	cfg.Notifications = false
	cfg.BlocklistFile = filepath.Join(root, "blocklist.txt")
	os.WriteFile(cfg.BlocklistFile, []byte(fileSHA(t, payload)+" test payload\n"), 0o644)
	os.MkdirAll(cfg.WatchDirs[0].Path, 0o755)
	cfgPath := filepath.Join(root, "config.json")
	b, _ := json.Marshal(cfg)
	os.WriteFile(cfgPath, b, 0o644)
	home := filepath.Join(root, "home")
	os.MkdirAll(home, 0o700)
	indexDir := filepath.Join(cfg.DataDir, "index")

	scan := func(paths ...string) {
		t.Helper()
		c := exec.Command(binchk, append([]string{"scan", "-config", cfgPath}, paths...)...)
		c.Env = append(os.Environ(), "HOME="+home)
		out, err := c.CombinedOutput()
		var ee *exec.ExitError
		if err != nil && !(errors.As(err, &ee) && ee.ExitCode() <= 3) {
			t.Fatalf("binchk scan: %v\n%s", err, out)
		}
		t.Logf("scan: %s", bytes.TrimSpace(bytes.SplitN(out, []byte("\n"), 2)[0]))
	}
	type result struct{ Path, Outcome, HTML string }
	look := func(path string) result {
		t.Helper()
		out, err := exec.Command(lookupBin, indexDir, path).Output()
		if err != nil {
			t.Fatalf("lookup %s: %v", path, err)
		}
		var r result
		sc := bufio.NewScanner(bytes.NewReader(out))
		sc.Buffer(nil, 4<<20)
		if !sc.Scan() || json.Unmarshal(sc.Bytes(), &r) != nil {
			t.Fatalf("lookup output %q", out)
		}
		t.Logf("lookup %s: %s", filepath.Base(path), r.Outcome)
		return r
	}
	// expect checks that path previews as name's card with verdict; banner
	// says whether the "matched by contents" banner must be there.
	expect := func(path, name, verdict string, banner bool) result {
		t.Helper()
		r := look(path)
		ok := strings.Contains(r.HTML, "<h1>"+name+"</h1>") && strings.Contains(r.HTML, `class="pill">`+verdict+"<") &&
			strings.Contains(r.HTML, "Matched by contents") == banner
		if !ok {
			t.Errorf("%s: want %s card (%s, banner %v); got %s:\n%s", path, name, verdict, banner, r.Outcome, excerpt(r.HTML))
		}
		return r
	}
	notChecked := func(path string) {
		t.Helper()
		if r := look(path); !strings.Contains(r.HTML, "Not checked by binchk") {
			t.Errorf("%s: want Not checked; got %s:\n%s", path, r.Outcome, excerpt(r.HTML))
		}
	}

	// Bundles sharing a main executable keep their own cards.
	apps := filepath.Join(root, "apps")
	benign := makeBundle(t, apps, "Benign", "Tool", "/bin/echo", nil)
	trojan := makeBundle(t, apps, "Trojan", "Tool", "/bin/echo", map[string]string{"Contents/Frameworks/libpayload.dylib": payload})
	scan(trojan)
	scan(benign)
	expect(trojan, "Trojan.app", "Malicious", false)
	expect(benign, "Benign.app", "Suspicious", false)
	expect(trojan+"/", "Trojan.app", "Malicious", false)
	// Through a symlinked folder the reader finds the pointer by the
	// resolved path; an item scanned through such a folder is found by its
	// real path too (binchk writes both spellings, like /tmp and
	// /private/tmp).
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(apps, alias); err != nil {
		t.Fatal(err)
	}
	expect(filepath.Join(alias, "Trojan.app"), "Trojan.app", "Malicious", false)
	viaAlias := makeBundle(t, apps, "ViaAlias", "Tool", "/bin/echo", nil)
	scan(filepath.Join(alias, "ViaAlias.app"))
	expect(viaAlias, "ViaAlias.app", "Suspicious", false)

	// An unanalysed copy of a bundle is matched by contents, with a banner.
	tcopy := filepath.Join(root, "elsewhere", "Trojan copy.app")
	os.MkdirAll(filepath.Dir(tcopy), 0o755)
	if out, err := exec.Command("cp", "-R", trojan, tcopy).CombinedOutput(); err != nil {
		t.Fatalf("cp: %v %s", err, out)
	}
	r := expect(tcopy, "Trojan.app", "Malicious", true)
	if !strings.Contains(r.HTML, "analysed as <b>Trojan.app</b>") {
		t.Errorf("banner does not name the analysed item:\n%s", excerpt(r.HTML))
	}
	// A bundle changed after its analysis is not that bundle any more.
	os.WriteFile(filepath.Join(benign, "Contents/Resources-added"), []byte("x"), 0o644)
	notChecked(benign)

	// Identical bare files under different names keep their own cards.
	files := filepath.Join(root, "files")
	os.MkdirAll(files, 0o755)
	plain := filepath.Join(files, "hello")
	double := filepath.Join(files, "hello.pdf.exe")
	copyFile(t, benignSample, plain)
	copyFile(t, benignSample, double)
	scan(double)
	scan(plain)
	expect(double, "hello.pdf.exe", "Suspicious", false)
	expect(plain, "hello", "Clean", false)
	// An unanalysed copy falls back to the most recent analysis of the
	// same bytes; the banner escapes what it shows.
	odd := filepath.Join(files, `odd<img src=x>&"q"`)
	copyFile(t, evilSample, odd)
	scan(odd)
	ecopy := filepath.Join(root, "elsewhere", "copy")
	copyFile(t, evilSample, ecopy)
	r = look(ecopy)
	if !strings.Contains(r.HTML, "Matched by contents") || !strings.Contains(r.HTML, "odd&lt;img src=x&gt;&amp;&quot;q&quot;") ||
		strings.Contains(r.HTML, "<img src=x>") {
		t.Errorf("content fallback banner: %s\n%s", r.Outcome, excerpt(r.HTML))
	}

	// A bundle whose CFBundleExecutable leaves it is never matched.
	esc := makeBundle(t, apps, "E", "../../../benign-outside", "", map[string]string{"Contents/MacOS/E": payload})
	scan(esc)
	notChecked(esc)

	// The watch pipeline writes the same index.
	a, err := New(cfg, false, "test")
	if err != nil {
		t.Fatal(err)
	}
	a.Log.SetOutput(io.Discard)
	a.notifier = func(string, string, string, notify.Urgency) {}
	h := &harness{App: a, root: root, watch: cfg.WatchDirs[0].Path, events: make(chan Event, 256)}
	a.Subscribe(func(ev Event) { h.events <- ev })
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Stop)
	dropped := filepath.Join(h.watch, "invoice")
	copyFile(t, evilSample, dropped)
	h.finished(t, dropped)
	expect(dropped, "invoice", "Malicious", false)
	wapp := filepath.Join(h.watch, "W.app")
	staging := makeBundle(t, filepath.Join(root, "staging"), "W", "Tool", "/bin/echo", nil)
	time.Sleep(50 * time.Millisecond)
	if err := os.Rename(staging, wapp); err != nil {
		t.Fatal(err)
	}
	h.finished(t, wapp)
	expect(wapp, "W.app", "Suspicious", false)
	// Benign.app's card is still its own after another bundle with the same
	// main executable was analysed.
	expect(trojan, "Trojan.app", "Malicious", false)
}

// excerpt is the card's identifying part, for failure messages.
func excerpt(html string) string {
	if i := strings.Index(html, "<body"); i >= 0 {
		html = html[i:]
	}
	if len(html) > 1500 {
		html = html[:1500]
	}
	return html
}
