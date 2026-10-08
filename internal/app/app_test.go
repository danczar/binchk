package app

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danczar/binchk/internal/config"
	"github.com/danczar/binchk/internal/findertag"
	"github.com/danczar/binchk/internal/index"
	"github.com/danczar/binchk/internal/legacy"
	"github.com/danczar/binchk/internal/notify"
)

// buildSample compiles one of the analyser's inert test programs for
// linux/amd64, so the verdict does not depend on the host's signature
// checks.
func buildSample(t *testing.T, pkg string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), pkg)
	cmd := exec.Command("go", "build", "-trimpath", "-o", path, "./"+pkg)
	cmd.Dir = filepath.Join("..", "analyze", "testdata")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=-mod=mod")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, b)
	}
	return path
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	// Write under a temporary name, then rename: like a browser finishing a
	// download.
	tmp := dst + ".part"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	out.Close()
	if err := os.Rename(tmp, dst); err != nil {
		t.Fatal(err)
	}
}

type note struct {
	title, body, open string
	urgency           notify.Urgency
}

type harness struct {
	*App
	root, watch string
	events      chan Event
	mu          sync.Mutex
	notes       []note
}

func (h *harness) notifications() []note {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]note{}, h.notes...)
}

func testConfig(root string) *config.Config {
	cfg := config.Default()
	cfg.WatchDirs = []config.WatchDir{{Path: filepath.Join(root, "watch")}}
	cfg.DataDir = filepath.Join(root, "data")
	cfg.RulesFile, cfg.BlocklistFile = "", ""
	cfg.AllowlistFile = filepath.Join(root, "allowlist.txt")
	cfg.SettleDelay = config.Duration(200 * time.Millisecond)
	return cfg
}

// newHarness builds an app over a scratch folder; prepare may adjust the
// config or fabricate state before the app starts.
func newHarness(t *testing.T, prepare func(cfg *config.Config)) *harness {
	t.Helper()
	root := t.TempDir()
	cfg := testConfig(root)
	os.MkdirAll(cfg.WatchDirs[0].Path, 0o755)
	if prepare != nil {
		prepare(cfg)
	}
	a, err := New(cfg, false, "test")
	if err != nil {
		t.Fatal(err)
	}
	a.Log.SetOutput(io.Discard)
	h := &harness{App: a, root: root, watch: cfg.WatchDirs[0].Path, events: make(chan Event, 256)}
	a.notifier = func(title, body, open string, u notify.Urgency) {
		h.mu.Lock()
		h.notes = append(h.notes, note{title, body, open, u})
		h.mu.Unlock()
	}
	a.Subscribe(func(ev Event) { h.events <- ev })
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Stop)
	return h
}

// finished waits for the analysis of path to finish.
func (h *harness) finished(t *testing.T, path string) *Event {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case ev := <-h.events:
			if ev.Kind == ScanFinished && ev.Path == path {
				return &ev
			}
		case <-deadline:
			t.Fatalf("timed out waiting for the analysis of %s", path)
		}
	}
}

// quiet fails if any analysis starts within d.
func (h *harness) quiet(t *testing.T, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case ev := <-h.events:
			if ev.Kind == ScanStarted {
				t.Fatalf("unexpected analysis of %s", ev.Path)
			}
		case <-deadline:
			return
		}
	}
}

func checkIndexed(t *testing.T, x *index.Index, path string, e *index.Entry) {
	t.Helper()
	if !index.IsDigest(e.SHA256) {
		t.Fatalf("entry has no digest: %+v", e)
	}
	got, err := x.Get(e.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 || got.Path != path || got.Verdict != e.Verdict || got.ReportPath != e.ReportPath ||
		got.BinchkVersion != "test" || got.FileName != filepath.Base(path) || got.Time().IsZero() {
		t.Fatalf("index entry %+v", got)
	}
	if _, err := os.Stat(got.ReportPath); err != nil {
		t.Fatalf("full report: %v", err)
	}
	card, err := os.ReadFile(x.CardPath(e.SHA256))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(card), e.Verdict) || strings.Contains(strings.ToLower(string(card)), "<script") {
		t.Fatalf("card:\n%s", card)
	}
	p, err := x.Pointer(path)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := IdentityStat(path)
	if p.SHA256 != e.SHA256 || !p.Matches(st) {
		t.Fatalf("pointer %+v does not match %s", p, path)
	}
	for _, f := range []string{x.EntryPath(e.SHA256), x.CardPath(e.SHA256), x.PointerPath(path)} {
		if st, err := os.Stat(f); err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o644) {
			t.Fatalf("%s: %v %v", f, st, err)
		}
	}
}

func tags(t *testing.T, path string) []string {
	t.Helper()
	tg, err := findertag.Get(path)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func TestEndToEnd(t *testing.T) {
	evil := buildSample(t, "evil")
	benign := buildSample(t, "benign")
	h := newHarness(t, nil)

	// A malicious download: analysed where it is, reported, indexed,
	// tagged and announced.
	target := filepath.Join(h.watch, "invoice")
	t0 := time.Now()
	copyFile(t, evil, target)
	ev := h.finished(t, target)
	e := ev.Entry
	t.Logf("verdict=%s score=%d, file dropped -> report ready in %s", e.Verdict, e.Score, time.Since(t0))
	if e.Verdict != "Malicious" {
		t.Fatalf("verdict %s: %s", e.Verdict, e.Summary)
	}
	if st, err := os.Stat(target); err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o755) {
		t.Fatalf("file not left in place untouched: %v %v", st, err)
	}
	checkIndexed(t, h.Index(), target, e)
	if findertag.Supported() {
		if got := tags(t, target); len(got) != 1 || got[0] != "binchk: Malicious\n6" {
			t.Fatalf("tags %q", got)
		}
	}
	notes := h.notifications()
	if len(notes) != 1 || notes[0].title != "Malicious: invoice" || notes[0].urgency != notify.Critical ||
		!strings.HasSuffix(notes[0].body, "Open binchk ▸ Recent reports.") || strings.Contains(strings.ToLower(notes[0].body), "click") {
		t.Fatalf("notifications %+v", notes)
	}
	t.Logf("notification: %s — %s", notes[0].title, notes[0].body)
	// Writing the tag is a metadata change: no second analysis.
	h.quiet(t, 1500*time.Millisecond)

	// A clean download: indexed for the Quick Look card, but neither tagged
	// nor announced.
	clean := filepath.Join(h.watch, "hello")
	copyFile(t, benign, clean)
	ce := h.finished(t, clean).Entry
	if ce.Verdict != "Clean" {
		t.Fatalf("benign sample: %s %s", ce.Verdict, ce.Summary)
	}
	checkIndexed(t, h.Index(), clean, ce)
	if findertag.Supported() {
		if got := tags(t, clean); len(got) != 0 {
			t.Fatalf("clean file tagged %q", got)
		}
	}
	if n := len(h.notifications()); n != 1 {
		t.Fatalf("%d notifications after a clean file", n)
	}
	if r := h.Recent(); len(r) != 2 || r[0].Path != clean || r[1].Path != target {
		t.Fatalf("recent %+v", r)
	}

	// Mark as safe: allowlisted, untagged, recorded in the index.
	if err := h.MarkSafe(e.SHA256); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(h.root, "allowlist.txt")); !strings.Contains(string(b), e.SHA256) {
		t.Fatalf("allowlist: %q", b)
	}
	if findertag.Supported() {
		if got := tags(t, target); len(got) != 0 {
			t.Fatalf("tag not removed: %q", got)
		}
	}
	got, _ := h.Index().Get(e.SHA256)
	if !got.MarkedSafe {
		t.Fatal("index entry not marked safe")
	}
	if card, _ := os.ReadFile(h.Index().CardPath(e.SHA256)); !strings.Contains(string(card), "marked this file as safe") {
		t.Fatal("card does not say it was marked safe")
	}
	if r := h.Recent(); !r[1].MarkedSafe {
		t.Fatal("recent entry not marked safe")
	}
	h.quiet(t, 1500*time.Millisecond)

	// The same content downloaded again is trusted: Clean, no tag, no
	// notification.
	again := filepath.Join(h.watch, "invoice (1)")
	copyFile(t, evil, again)
	ae := h.finished(t, again).Entry
	if ae.Verdict != "Clean" || !ae.MarkedSafe {
		t.Fatalf("allowlisted copy: %+v", ae)
	}
	if findertag.Supported() {
		if got := tags(t, again); len(got) != 0 {
			t.Fatalf("allowlisted file tagged %q", got)
		}
	}
	if n := len(h.notifications()); n != 1 {
		t.Fatalf("%d notifications after an allowlisted file", n)
	}
}

// Notification and tag policy follow the config.
func TestVerdictPolicy(t *testing.T) {
	evil := buildSample(t, "evil")
	benign := buildSample(t, "benign")
	h := newHarness(t, func(cfg *config.Config) {
		cfg.NotifyVerdicts = []string{"Clean"}
		cfg.TagVerdicts = []string{"Clean", "Suspicious"}
	})
	bad := filepath.Join(h.watch, "bad")
	copyFile(t, evil, bad)
	h.finished(t, bad)
	good := filepath.Join(h.watch, "good")
	copyFile(t, benign, good)
	h.finished(t, good)

	notes := h.notifications()
	if len(notes) != 1 || notes[0].title != "Clean: good" {
		t.Fatalf("notifications %+v", notes)
	}
	if findertag.Supported() {
		if got := tags(t, bad); len(got) != 0 {
			t.Fatalf("Malicious tagged although not configured: %q", got)
		}
		if got := tags(t, good); len(got) != 1 || got[0] != "binchk: Clean\n2" {
			t.Fatalf("clean tags %q", got)
		}
	}

	// finder_tags off: files are never touched; notifications off: silence.
	h2 := newHarness(t, func(cfg *config.Config) { cfg.FinderTags, cfg.Notifications = false, false })
	p := filepath.Join(h2.watch, "bad")
	copyFile(t, evil, p)
	h2.finished(t, p)
	if len(h2.notifications()) != 0 {
		t.Fatal("notified with notifications off")
	}
	if findertag.Supported() {
		if got := tags(t, p); len(got) != 0 {
			t.Fatalf("tagged with finder_tags off: %q", got)
		}
	}
}

// Clearing recent reports hides them from the menu (also after a restart)
// without deleting anything.
func TestClearRecent(t *testing.T) {
	benign := buildSample(t, "benign")
	h := newHarness(t, nil)
	p := filepath.Join(h.watch, "hello")
	copyFile(t, benign, p)
	e := h.finished(t, p).Entry
	if len(h.Recent()) != 1 {
		t.Fatal("not in recent")
	}
	if err := h.ClearRecent(); err != nil {
		t.Fatal(err)
	}
	if len(h.Recent()) != 0 {
		t.Fatal("still in recent")
	}
	if _, err := h.Index().Get(e.SHA256); err != nil {
		t.Fatal("index entry deleted")
	}
	if _, err := os.Stat(e.ReportPath); err != nil {
		t.Fatal("report deleted")
	}
	a2, err := New(h.cfg, false, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(a2.Recent()) != 0 {
		t.Fatal("cleared entries back after restart")
	}

	// Entries reload on restart when not cleared.
	time.Sleep(1100 * time.Millisecond) // clear time has second precision
	q := filepath.Join(h.watch, "hello2")
	b, _ := os.ReadFile(benign)
	os.WriteFile(filepath.Join(h.root, "x"), append(b, "x"...), 0o755)
	copyFile(t, filepath.Join(h.root, "x"), q)
	h.finished(t, q)
	a3, _ := New(h.cfg, false, "test")
	if r := a3.Recent(); len(r) != 1 || r[0].Path != q {
		t.Fatalf("recent after restart: %+v", r)
	}
}

// v0.1.x vault items come back to their folders on first start, get
// analysed in place exactly once, and the user is told once.
func TestLegacyMigration(t *testing.T) {
	evil := buildSample(t, "evil")
	var target, other string
	h := newHarness(t, func(cfg *config.Config) {
		watch := cfg.WatchDirs[0].Path
		vault := legacy.VaultDir(cfg.DataPath())
		os.MkdirAll(vault, 0o700)
		target = filepath.Join(watch, "tool")
		other = filepath.Join(filepath.Dir(watch), "elsewhere", "tool2")
		for i, p := range []string{target, other} {
			id := fmt.Sprintf("20260101-000000-0000000%d", i)
			stored := filepath.Join(vault, id+".quarantined")
			b, _ := os.ReadFile(evil)
			os.WriteFile(stored, append(b, byte(i)), 0o400)
			rec, _ := json.Marshal(map[string]any{
				"id": id, "name": filepath.Base(p), "original_path": p, "stored_path": stored,
				"mode": fs.FileMode(0o755), "quarantined_at": time.Now(), "status": "quarantined",
			})
			os.WriteFile(filepath.Join(vault, id+".json"), rec, 0o600)
		}
	})
	seen := map[string]bool{}
	for len(seen) < 2 {
		select {
		case ev := <-h.events:
			if ev.Kind == ScanFinished {
				if seen[ev.Path] {
					t.Fatalf("%s analysed twice", ev.Path)
				}
				seen[ev.Path] = true
			}
		case <-time.After(20 * time.Second):
			t.Fatalf("restored files not analysed: %v", seen)
		}
	}
	if !seen[target] || !seen[other] {
		t.Fatalf("analysed %v", seen)
	}
	h.quiet(t, 1500*time.Millisecond)
	for _, p := range []string{target, other} {
		if st, err := os.Stat(p); err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o755) {
			t.Fatalf("%s: %v %v", p, st, err)
		}
		if _, err := h.Index().Pointer(p); err != nil {
			t.Fatalf("%s not indexed: %v", p, err)
		}
	}
	if _, err := os.Stat(legacy.VaultDir(h.DataDir())); !os.IsNotExist(err) {
		t.Fatal("vault still there")
	}
	notes := h.notifications()
	if len(notes) == 0 || notes[0].title != "binchk no longer quarantines downloads" || notes[0].body != "2 files were returned to their original folders." {
		t.Fatalf("notifications %+v", notes)
	}
}

// An .app dropped into a watched folder is analysed as a unit, in place,
// and indexed under its main executable.
func TestBundleEndToEnd(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("app bundles are handled on macOS")
	}
	evil := buildSample(t, "evil")
	h := newHarness(t, nil)

	// Build the app elsewhere, then move it in (like Archive Utility does).
	staging := filepath.Join(h.root, "staging", "Tool.app")
	exe := filepath.Join(staging, "Contents/MacOS/Tool")
	os.MkdirAll(filepath.Dir(exe), 0o755)
	copyFile(t, evil, exe)
	os.WriteFile(filepath.Join(staging, "Contents/Info.plist"), []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>Tool</string></dict></plist>`), 0o644)
	target := filepath.Join(h.watch, "Tool.app")
	t0 := time.Now()
	if err := os.Rename(staging, target); err != nil {
		t.Fatal(err)
	}
	e := h.finished(t, target).Entry
	t.Logf("verdict=%s: app dropped -> report ready in %s", e.Verdict, time.Since(t0))
	st, err := os.Stat(filepath.Join(target, "Contents/MacOS/Tool"))
	if err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("bundle not left in place: %v %v", st, err)
	}
	checkIndexed(t, h.Index(), target, e)
	if e.Verdict == "Suspicious" || e.Verdict == "Malicious" {
		if got := tags(t, target); len(got) != 1 || !strings.HasPrefix(got[0], "binchk: ") {
			t.Fatalf("bundle tags %q", got)
		}
	}
	h.quiet(t, 2500*time.Millisecond)
}
