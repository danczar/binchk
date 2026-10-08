package index

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/danczar/binchk/internal/analyze"
)

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sampleReport(name, sha string, at time.Time) *analyze.Report {
	return &analyze.Report{
		FileName: name, Format: "Mach-O (universal)", Arches: []string{"arm64", "x86_64"}, Size: 123456,
		Hashes:  analyze.Hashes{SHA256: strings.ToUpper(sha)},
		Verdict: analyze.VerdictSuspicious, Score: 42, Summary: "2 high — Reads browser credential stores",
		Signature: analyze.Signature{Signer: "Developer ID Application: Example (ABCDE12345)", Notarized: true,
			Gatekeeper: "accepted: Notarized Developer ID"},
		Findings: []analyze.Finding{
			{Title: "low one", Severity: analyze.Low},
			{Title: "high one", Severity: analyze.High},
			{Title: "info", Severity: analyze.Info},
			{Title: "medium", Severity: analyze.Medium},
			{Title: "high two", Severity: analyze.High},
			{Title: "critical", Severity: analyze.Critical},
			{Title: "low two", Severity: analyze.Low},
		},
		AnalyzedAt: at,
	}
}

func TestNewEntry(t *testing.T) {
	sha := digest("a")
	at := time.Date(2026, 10, 8, 14, 3, 4, 5e8, time.FixedZone("x", 3600))
	e := NewEntry(sampleReport("tool.dmg", sha, at), "/Users/u/Downloads/tool.dmg", "/r/x.html", "v0.2.0", false)
	if e.SHA256 != sha || e.Version != 1 || e.AnalyzedAt != "2026-10-08T13:03:04Z" || e.BinchkVersion != "v0.2.0" ||
		e.Signer == "" || !e.Notarized || e.Gatekeeper == "" || e.Verdict != "Suspicious" || e.Score != 42 {
		t.Fatalf("%+v", e)
	}
	want := []string{"critical:critical", "high:high one", "high:high two", "medium:medium", "low:low one"}
	if len(e.TopFindings) != len(want) {
		t.Fatalf("top findings %+v", e.TopFindings)
	}
	for i, f := range e.TopFindings {
		if f.Severity+":"+f.Title != want[i] {
			t.Fatalf("top findings %+v", e.TopFindings)
		}
	}
	// The JSON uses exactly the contract's keys.
	b, _ := json.Marshal(e)
	var m map[string]any
	json.Unmarshal(b, &m)
	for _, k := range []string{"version", "sha256", "file_name", "path", "format", "verdict", "score", "summary", "signer",
		"notarized", "gatekeeper", "top_findings", "report_path", "analyzed_at", "marked_safe", "binchk_version"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %s", k)
		}
		delete(m, k)
	}
	if len(m) != 0 {
		t.Errorf("extra keys %v", m)
	}
	// No findings: an empty array, never null.
	r := sampleReport("x", sha, at)
	r.Findings = nil
	if b, _ := json.Marshal(NewEntry(r, "/x", "", "", false)); !strings.Contains(string(b), `"top_findings":[]`) {
		t.Fatalf("%s", b)
	}
}

func TestPutGetPointer(t *testing.T) {
	data := filepath.Join(t.TempDir(), "data")
	x, err := Open(data)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "tool.dmg")
	os.WriteFile(file, []byte("content"), 0o644)
	st, _ := os.Stat(file)
	sha := digest("content")
	e := NewEntry(sampleReport("tool.dmg", sha, time.Now()), file, "/r/x.html", "v", false)
	if err := x.Put(e, Extra{Arches: []string{"arm64"}, Size: 7}); err != nil {
		t.Fatal(err)
	}
	if err := x.Point(file, sha, st); err != nil {
		t.Fatal(err)
	}

	got, err := x.Get(sha)
	if err != nil || got.Path != file || got.Verdict != "Suspicious" {
		t.Fatalf("%+v %v", got, err)
	}
	p, err := x.Pointer(file)
	if err != nil || p.SHA256 != sha || !p.Matches(st) {
		t.Fatalf("%+v %v", p, err)
	}
	// The pointer's name is the SHA-256 of the path's bytes.
	if filepath.Base(x.PointerPath(file)) != digest(file)+".json" {
		t.Fatal("pointer name")
	}
	// A changed file no longer matches.
	os.WriteFile(file, []byte("changed!"), 0o644)
	st2, _ := os.Stat(file)
	if p.Matches(st2) {
		t.Fatal("pointer matches a changed file")
	}

	// Layout and permissions: hex names only, no temporary files left.
	for _, d := range []string{filepath.Join(data, "index"), filepath.Join(data, "index", "paths")} {
		des, _ := os.ReadDir(d)
		for _, de := range des {
			if de.IsDir() {
				continue
			}
			stem := strings.TrimSuffix(strings.TrimSuffix(de.Name(), ".json"), ".html")
			if !IsDigest(stem) {
				t.Errorf("unexpected file %s", de.Name())
			}
			info, _ := de.Info()
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
				t.Errorf("%s mode %v", de.Name(), info.Mode())
			}
		}
		if st, _ := os.Stat(d); runtime.GOOS != "windows" && st.Mode().Perm() != 0o755 {
			t.Errorf("%s mode %v", d, st.Mode())
		}
	}

	// Invalid digests are refused, never used as names.
	bad := *e
	bad.SHA256 = "../../etc/passwd"
	if err := x.Put(&bad, Extra{}); err == nil {
		t.Fatal("accepted a bad digest")
	}
	if err := x.Point(file, "nothex", st); err == nil {
		t.Fatal("accepted a bad pointer digest")
	}
	if _, err := x.Get("../x"); err == nil {
		t.Fatal("Get accepted a bad digest")
	}
}

func TestCard(t *testing.T) {
	x, _ := Open(t.TempDir())
	sha := digest("evil")
	r := sampleReport(`<img src=x onerror=alert(1)>.dmg`, sha, time.Now())
	r.Findings[1].Title = `</li><script>alert("x")</script>`
	r.Summary = `<b>bold</b> & "quoted"`
	e := NewEntry(r, `/Users/u/Downloads/<img src=x onerror=alert(1)>.dmg`, "/r/x.html", "v", false)
	if err := x.Put(e, Extra{Arches: []string{"arm64", "x86_64"}, Size: 2 << 20}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(x.CardPath(sha))
	if err != nil {
		t.Fatal(err)
	}
	card := string(b)
	lower := strings.ToLower(card)
	for _, bad := range []string{"<script", "<img", "<b>bold", "http://", "https://", "@import", "url("} {
		if strings.Contains(lower, bad) {
			t.Errorf("card contains %q", bad)
		}
	}
	for _, want := range []string{"Suspicious", "&lt;img src=x onerror=alert(1)&gt;.dmg", "42", "arm64, x86_64", "2.0 MiB",
		"Developer ID Application: Example (ABCDE12345)", "Notarized", "accepted: Notarized Developer ID",
		"s-critical", "Full report: binchk menu ▸ Recent reports", "prefers-color-scheme:dark"} {
		if !strings.Contains(card, want) {
			t.Errorf("card lacks %q", want)
		}
	}
	if n := strings.Count(card, "<li>"); n != MaxTopFindings {
		t.Errorf("%d findings shown", n)
	}
	if strings.Contains(card, "marked this file as safe") {
		t.Error("not marked safe yet")
	}

	// Mark safe re-renders the card and keeps the extra details from the
	// full JSON report next to the HTML one.
	dir := t.TempDir()
	e.ReportPath = filepath.Join(dir, "r.html")
	os.WriteFile(filepath.Join(dir, "r.json"), []byte(`{"arches":["arm64e"],"size":5}`), 0o644)
	x.Put(e, Extra{})
	got, err := x.SetMarkedSafe(sha, true)
	if err != nil || !got.MarkedSafe {
		t.Fatalf("%+v %v", got, err)
	}
	b, _ = os.ReadFile(x.CardPath(sha))
	if !strings.Contains(string(b), "marked this file as safe") || !strings.Contains(string(b), "arm64e") {
		t.Fatalf("card after mark safe:\n%s", b)
	}
	if again, _ := x.Get(sha); !again.MarkedSafe {
		t.Fatal("marked_safe not stored")
	}
}

func TestRecent(t *testing.T) {
	x, _ := Open(t.TempDir())
	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	for i, name := range []string{"a", "b", "c", "d"} {
		e := NewEntry(sampleReport(name, digest(name), base.Add(time.Duration(i)*time.Minute)), "/d/"+name, "", "v", false)
		if err := x.Put(e, Extra{}); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(x.Dir(), "notes.json"), []byte("{}"), 0o644) // ignored: not a digest
	got, err := x.Recent(3, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].FileName != "d" || got[1].FileName != "c" || got[2].FileName != "b" {
		t.Fatalf("recent %+v", got)
	}
	got, _ = x.Recent(10, base.Add(90*time.Second))
	if len(got) != 2 || got[0].FileName != "d" {
		t.Fatalf("since: %+v", got)
	}
}

// The signing line only appears where code signing applies, and the
// notarization note only for Apple formats.
func TestCardSigningLine(t *testing.T) {
	x, _ := Open(t.TempDir())
	for _, c := range []struct {
		format       string
		sign, notary bool
	}{
		{"ELF", false, false},
		{"script", false, false},
		{"PE", true, false},
		{"Mach-O", true, true},
		{"Application bundle", true, true},
	} {
		sha := digest("sig-" + c.format)
		r := sampleReport("f", sha, time.Now())
		r.Format = c.format
		r.Signature = analyze.Signature{}
		if err := x.Put(NewEntry(r, "/d/f", "/r/f.html", "v", false), Extra{}); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(x.CardPath(sha))
		card := string(b)
		if got := strings.Contains(card, "Not signed by an identified developer"); got != c.sign {
			t.Errorf("%s: signing line shown = %v, want %v", c.format, got, c.sign)
		}
		if got := strings.Contains(card, "otarized"); got != c.notary {
			t.Errorf("%s: notarization shown = %v, want %v", c.format, got, c.notary)
		}
	}
}
