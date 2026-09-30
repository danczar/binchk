package app

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/danczar/binchk/internal/config"
)

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

func waitEvent(t *testing.T, ch <-chan Event, kind EventKind, timeout time.Duration) Event {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-ch:
			if ev.Kind == kind {
				return ev
			}
		case <-deadline:
			t.Fatalf("timed out waiting for event %d", kind)
		}
	}
}

func TestEndToEnd(t *testing.T) {
	root := t.TempDir()
	watch := filepath.Join(root, "watch")
	os.MkdirAll(watch, 0o755)
	cfg := config.Default()
	cfg.WatchDirs = []config.WatchDir{{Path: watch}}
	cfg.DataDir = filepath.Join(root, "data")
	cfg.Notifications = false
	cfg.RulesFile, cfg.BlocklistFile = "", ""
	cfg.AllowlistFile = filepath.Join(root, "allowlist.txt")
	cfg.SettleDelay = config.Duration(200 * time.Millisecond)

	a, err := New(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	a.Log.SetOutput(io.Discard)
	events := make(chan Event, 64)
	a.Subscribe(func(ev Event) { events <- ev })
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	defer a.Stop()

	exe, _ := os.Executable() // the test binary: a real native executable
	target := filepath.Join(watch, "tool")
	t0 := time.Now()
	copyFile(t, exe, target)

	ev := waitEvent(t, events, ScanFinished, 15*time.Second)
	total := time.Since(t0)
	e := ev.Entry
	t.Logf("verdict=%s score=%d, file dropped -> report ready in %s", e.Verdict, e.Score, total)
	if total > 15*time.Second {
		t.Errorf("pipeline took %s, budget is 15s", total)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("original file still present after quarantine")
	}
	st, err := os.Stat(e.StoredPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o111 != 0 {
		t.Errorf("quarantined file is executable: %v", st.Mode())
	}
	if _, err := os.Stat(e.ReportPath); err != nil {
		t.Fatalf("report missing: %v", err)
	}
	if len(a.Items()) != 1 {
		t.Fatalf("items = %d, want 1", len(a.Items()))
	}

	// Restore: file returns with its permissions; the move back must not
	// trigger another scan; the hash becomes trusted.
	dst, err := a.Restore(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if dst != target {
		t.Errorf("restored to %s, want %s", dst, target)
	}
	if st, err := os.Stat(target); err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o755) {
		t.Fatalf("restored file: %v %v", st, err)
	}
	select {
	case ev := <-drainUntil(events, ScanStarted, 1500*time.Millisecond):
		t.Fatalf("restore re-triggered a scan: %+v", ev)
	default:
	}
	if len(a.Items()) != 0 {
		t.Fatalf("items after restore = %d", len(a.Items()))
	}

	// Same content under a new name: allowlisted, so auto-restored.
	target2 := filepath.Join(watch, "tool-copy")
	copyFile(t, exe, target2)
	waitEvent(t, events, ScanFinished, 15*time.Second)
	if _, err := os.Stat(target2); err != nil {
		t.Fatalf("allowlisted file was not auto-restored: %v", err)
	}
	if len(a.Items()) != 0 {
		t.Fatalf("allowlisted file left in quarantine")
	}

	// A different binary, then Delete.
	other := filepath.Join(root, "other")
	b, _ := os.ReadFile(exe)
	os.WriteFile(other, append(b, "different"...), 0o755)
	copyFile(t, other, filepath.Join(watch, "other"))
	ev = waitEvent(t, events, ScanFinished, 15*time.Second)
	if err := a.Delete(ev.Entry.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ev.Entry.StoredPath); !os.IsNotExist(err) {
		t.Fatal("deleted file still in quarantine")
	}
}

// drainUntil returns a channel that yields the first event of kind within d.
func drainUntil(ch <-chan Event, kind EventKind, d time.Duration) <-chan Event {
	out := make(chan Event, 1)
	deadline := time.After(d)
	for {
		select {
		case ev := <-ch:
			if ev.Kind == kind {
				out <- ev
				return out
			}
		case <-deadline:
			return out
		}
	}
}

// An .app dropped into a watched folder is quarantined as a unit, analysed,
// and restored with its execute permissions intact.
func TestBundleEndToEnd(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("app bundles are handled on macOS")
	}
	root := t.TempDir()
	watch := filepath.Join(root, "watch")
	os.MkdirAll(watch, 0o755)
	cfg := config.Default()
	cfg.WatchDirs = []config.WatchDir{{Path: watch}}
	cfg.DataDir = filepath.Join(root, "data")
	cfg.Notifications = false
	cfg.RulesFile, cfg.BlocklistFile = "", ""
	cfg.AllowlistFile = filepath.Join(root, "allowlist.txt")
	cfg.SettleDelay = config.Duration(200 * time.Millisecond)
	a, err := New(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	a.Log.SetOutput(io.Discard)
	events := make(chan Event, 64)
	a.Subscribe(func(ev Event) { events <- ev })
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	defer a.Stop()

	// Build the app elsewhere, then move it in (like Archive Utility does).
	staging := filepath.Join(root, "staging", "Tool.app")
	exe := filepath.Join(staging, "Contents/MacOS/Tool")
	os.MkdirAll(filepath.Dir(exe), 0o755)
	self, _ := os.Executable()
	copyFile(t, self, exe)
	os.WriteFile(filepath.Join(staging, "Contents/Info.plist"), []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>Tool</string></dict></plist>`), 0o644)
	target := filepath.Join(watch, "Tool.app")
	t0 := time.Now()
	if err := os.Rename(staging, target); err != nil {
		t.Fatal(err)
	}
	ev := waitEvent(t, events, ScanFinished, 15*time.Second)
	t.Logf("verdict=%s: app dropped -> report ready in %s", ev.Entry.Verdict, time.Since(t0))
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("bundle still in the watched folder")
	}
	if !ev.Entry.Bundle {
		t.Fatal("entry not marked as bundle")
	}
	st, _ := os.Stat(filepath.Join(ev.Entry.StoredPath, "Contents/MacOS/Tool"))
	if st == nil || st.Mode().Perm()&0o111 != 0 {
		t.Fatalf("quarantined executable: %v", st)
	}
	if _, err := a.Restore(ev.Entry.ID); err != nil {
		t.Fatal(err)
	}
	st, _ = os.Stat(filepath.Join(target, "Contents/MacOS/Tool"))
	if st == nil || st.Mode().Perm()&0o111 == 0 {
		t.Fatalf("restored executable lost its exec bit: %v", st)
	}
	select {
	case ev := <-drainUntil(events, ScanStarted, 2500*time.Millisecond):
		t.Fatalf("restore re-triggered a scan: %+v", ev)
	default:
	}
}
