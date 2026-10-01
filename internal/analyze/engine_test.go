package analyze

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func newTestEngine(t *testing.T, budget time.Duration) *Engine {
	t.Helper()
	e, err := NewEngine(Options{Budget: budget})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func goBuild(t *testing.T, pkg, goos, goarch, out string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), out)
	cmd := exec.Command("go", "build", "-trimpath", "-o", path, "./"+pkg)
	cmd.Dir = "testdata"
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0", "GOFLAGS=-mod=mod")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s for %s/%s: %v\n%s", pkg, goos, goarch, err, b)
	}
	return path
}

func findingIDs(r *Report) map[string]Severity {
	m := map[string]Severity{}
	for _, f := range r.Findings {
		m[f.ID] = f.Severity
	}
	return m
}

var targets = []struct{ goos, goarch, format, name string }{
	{"windows", "amd64", "PE", "invoice.pdf.exe"},
	{"linux", "amd64", "ELF", "update"},
	{"darwin", "arm64", "Mach-O", "Installer"},
}

func TestEvilSamples(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	eng := newTestEngine(t, 10*time.Second)
	for _, tg := range targets {
		t.Run(tg.goos, func(t *testing.T) {
			path := goBuild(t, "evil", tg.goos, tg.goarch, tg.name)
			r := eng.Analyze(context.Background(), path, Meta{FileName: tg.name})
			if r.Format != tg.format {
				t.Fatalf("format = %q, want %q", r.Format, tg.format)
			}
			if r.Verdict != VerdictMalicious {
				t.Errorf("verdict = %s (score %d), want Malicious; %s", r.Verdict, r.Score, r.Summary)
			}
			ids := findingIDs(r)
			for _, want := range []string{"ransom-recovery-inhibit", "ransom-note", "miner-pool", "stealer-browsers",
				"stealer-cred-files", "stealer-wallets", "exfil-webhooks", "ioc-ip-url", "ioc-crypto", "mac-fake-password-prompt"} {
				if _, ok := ids[want]; !ok {
					t.Errorf("missing finding %s", want)
				}
			}
			if tg.goos == "windows" {
				if _, ok := ids["name-double-ext"]; !ok {
					t.Error("missing double-extension finding")
				}
			}
			if r.Toolchain.Language != "Go" {
				t.Errorf("toolchain = %+v", r.Toolchain)
			}
			if r.Hashes.SHA256 == "" || r.Hashes.MD5 == "" || r.Truncated {
				t.Errorf("hashes=%+v truncated=%v", r.Hashes, r.Truncated)
			}
			t.Logf("%s: %s score=%d in %s", tg.goos, r.Verdict, r.Score, r.Elapsed)
		})
	}
}

// TestUDIFTrailerEvasion: an appended disk image trailer must not hide an
// executable; it is analysed as such and the disguise is flagged.
func TestUDIFTrailerEvasion(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	eng := newTestEngine(t, 10*time.Second)
	for _, tg := range targets {
		t.Run(tg.goos, func(t *testing.T) {
			path := goBuild(t, "evil", tg.goos, tg.goarch, tg.name)
			appendKoly(t, path)
			r := eng.Analyze(context.Background(), path, Meta{FileName: tg.name})
			if r.Format != tg.format {
				t.Fatalf("format = %q, want %q", r.Format, tg.format)
			}
			if r.Verdict != VerdictMalicious {
				t.Errorf("verdict = %s (score %d), want Malicious; %s", r.Verdict, r.Score, r.Summary)
			}
			ids := findingIDs(r)
			for _, want := range []string{"udif-trailer", "ransom-note", "stealer-wallets"} {
				if _, ok := ids[want]; !ok {
					t.Errorf("missing finding %s", want)
				}
			}
		})
	}
}

// appendKoly appends a well-formed 512-byte UDIF trailer to path.
func appendKoly(t *testing.T, path string) {
	t.Helper()
	k := make([]byte, 512)
	copy(k, "koly\x00\x00\x00\x04\x00\x00\x02\x00")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(k); err != nil {
		t.Fatal(err)
	}
}

func TestBenignSamples(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	eng := newTestEngine(t, 10*time.Second)
	for _, tg := range targets {
		t.Run(tg.goos, func(t *testing.T) {
			path := goBuild(t, "benign", tg.goos, tg.goarch, "hello")
			r := eng.Analyze(context.Background(), path, Meta{})
			if r.Verdict != VerdictClean {
				t.Errorf("verdict = %s (score %d): %+v", r.Verdict, r.Score, r.Findings)
			}
		})
	}
}

func TestInjectionImports(t *testing.T) {
	cc, err := exec.LookPath("x86_64-w64-mingw32-gcc")
	if err != nil {
		t.Skip("mingw not installed")
	}
	out := filepath.Join(t.TempDir(), "inject.exe")
	if b, err := exec.Command(cc, "-O1", "-o", out, "testdata/inject.c").CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	r := newTestEngine(t, 10*time.Second).Analyze(context.Background(), out, Meta{})
	ids := findingIDs(r)
	if ids["api-injection"] != High {
		t.Errorf("api-injection = %v, want high; findings %+v", ids["api-injection"], r.Findings)
	}
	if ids["api-keylogging"] != Medium {
		t.Errorf("api-keylogging = %v, want medium", ids["api-keylogging"])
	}
	if r.Hashes.Imphash == "" {
		t.Error("no imphash")
	}
}

func TestBudgetTruncates(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	r := newTestEngine(t, time.Nanosecond).Analyze(context.Background(), exe, Meta{})
	if !r.Truncated {
		t.Error("expected a truncated report")
	}
	if r.Verdict == "" {
		t.Error("truncated report must still carry a verdict")
	}
}

func TestSelfIsClean(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	// binchk must not flag itself: its signatures are embedded compressed.
	path := filepath.Join(t.TempDir(), "binchk")
	cmd := exec.Command("go", "build", "-o", path, "github.com/danczar/binchk/cmd/binchk")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	r := newTestEngine(t, 10*time.Second).Analyze(context.Background(), path, Meta{})
	if r.Verdict != VerdictClean {
		t.Errorf("binchk flags itself: %s %d %+v", r.Verdict, r.Score, r.Findings)
	}
	_ = runtime.GOOS
}

func BenchmarkAnalyzeSelf(b *testing.B) {
	exe, _ := os.Executable()
	eng, _ := NewEngine(Options{Budget: 10 * time.Second})
	st, _ := os.Stat(exe)
	b.SetBytes(st.Size())
	for i := 0; i < b.N; i++ {
		eng.Analyze(context.Background(), exe, Meta{})
	}
}
