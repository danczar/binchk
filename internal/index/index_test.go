package index

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/danczar/binchk/internal/analyze"
	"github.com/danczar/binchk/internal/bundleid"
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

func bundleReport(name, mainSHA, fingerprint string, at time.Time) *analyze.Report {
	r := sampleReport(name, mainSHA, at)
	r.Format = "Application bundle"
	r.Hashes.Bundle = fingerprint
	return r
}

func TestNewEntry(t *testing.T) {
	sha := digest("a")
	at := time.Date(2026, 10, 8, 14, 3, 4, 5e8, time.FixedZone("x", 3600))
	path := "/Users/u/Downloads/tool.dmg"
	e := NewEntry(sampleReport("tool.dmg", sha, at), path, "/r/x.html", "v0.2.0", false)
	if e.SHA256 != sha || e.ContentKey != sha || e.TrustKey != sha || e.Kind != KindFile || e.EntryID != EntryID(path, sha) ||
		e.Version != 2 || e.AnalyzedAt != "2026-10-08T13:03:04Z" || e.BinchkVersion != "v0.2.0" ||
		e.Signer == "" || !e.Notarized || e.Gatekeeper == "" || e.Verdict != "Suspicious" || e.Score != 42 ||
		!slices.Equal(e.Paths, []string{path}) {
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
	for _, k := range []string{"version", "entry_id", "content_key", "trust_key", "kind", "sha256", "file_name", "path", "format",
		"verdict", "score", "summary", "signer", "notarized", "gatekeeper", "top_findings", "report_path",
		"analyzed_at", "marked_safe", "binchk_version", "paths"} {
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

	// A bundle is keyed by its fingerprint and trusted by its contents
	// digest, never by its main executable.
	fp, contents := digest("fingerprint"), digest("contents")
	br := bundleReport("T.app", sha, fp, at)
	br.Hashes.BundleContents = contents
	be := NewEntry(br, "/A/T.app", "", "", false)
	if be.Kind != KindBundle || be.ContentKey != fp || be.TrustKey != contents || be.SHA256 != sha || be.EntryID != EntryID("/A/T.app", fp) {
		t.Fatalf("bundle entry %+v", be)
	}
	// Without a contents digest it cannot be trusted, but is still indexed.
	if ue := NewEntry(bundleReport("T.app", sha, fp, at), "/A/T.app", "", "", false); ue.TrustKey != "" || ue.EntryID != be.EntryID {
		t.Fatalf("bundle without contents digest %+v", ue)
	}
	// Without a fingerprint it has no identity at all.
	if ne := NewEntry(bundleReport("T.app", sha, "", at), "/A/T.app", "", "", false); ne.EntryID != "" || ne.ContentKey != "" {
		t.Fatalf("bundle without fingerprint %+v", ne)
	}
}

func TestEntryID(t *testing.T) {
	k1, k2 := digest("1"), digest("2")
	ids := map[string]bool{}
	for _, id := range []string{EntryID("/a/x", k1), EntryID("/a/y", k1), EntryID("/a/x", k2), EntryID("/a/x\x00"+k1, "")} {
		if !IsDigest(id) || ids[id] {
			t.Fatalf("entry ids collide or are malformed: %v", ids)
		}
		ids[id] = true
	}
	if EntryID("/a/x", k1) != digest("v2\x00/a/x\x00"+k1) {
		t.Fatal("entry id definition")
	}
}

func fileState(t *testing.T, p string) *State {
	t.Helper()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return &State{Kind: KindFile, Size: st.Size(), MtimeUnixNs: st.ModTime().UnixNano()}
}

func TestPutGetPointerContent(t *testing.T) {
	data := filepath.Join(t.TempDir(), "data")
	x, err := Open(data)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "tool.dmg")
	os.WriteFile(file, []byte("content"), 0o644)
	st := fileState(t, file)
	sha := digest("content")
	e := NewEntry(sampleReport("tool.dmg", sha, time.Now()), file, "/r/x.html", "v", false)
	if err := x.Put(e, Extra{Arches: []string{"arm64"}, Size: 7}); err != nil {
		t.Fatal(err)
	}
	if err := x.Point(file, e, st); err != nil {
		t.Fatal(err)
	}
	if err := x.SetContent(e); err != nil {
		t.Fatal(err)
	}

	got, err := x.Get(e.EntryID)
	if err != nil || got.Path != file || got.Verdict != "Suspicious" || got.ContentKey != sha {
		t.Fatalf("%+v %v", got, err)
	}
	p, err := x.Pointer(file)
	if err != nil || p.Entry != e.EntryID || p.Kind != KindFile || !p.Matches(st) {
		t.Fatalf("%+v %v", p, err)
	}
	c, err := x.Content(sha)
	if err != nil || c.Entry != e.EntryID || c.Path != file || c.AnalyzedAt != e.AnalyzedAt || c.Version != 2 {
		t.Fatalf("content %+v %v", c, err)
	}
	// Names: the pointer is the SHA-256 of the path's bytes, the entry its
	// id, the content map its content key.
	if filepath.Base(x.PointerPath(file)) != digest(file)+".json" || filepath.Base(x.EntryPath(e.EntryID)) != e.EntryID+".json" ||
		filepath.Base(x.ContentPath(sha)) != sha+".json" {
		t.Fatal("names")
	}
	// The pointer JSON holds only a file's staleness data.
	var m map[string]any
	b, _ := os.ReadFile(x.PointerPath(file))
	json.Unmarshal(b, &m)
	if len(m) != 5 || m["version"] != 2.0 || m["kind"] != "file" || m["size"] != 7.0 || m["mtime_unix_ns"] == nil {
		t.Fatalf("file pointer %s", b)
	}
	// A changed file no longer matches; neither does another kind.
	os.WriteFile(file, []byte("changed!"), 0o644)
	if p.Matches(fileState(t, file)) {
		t.Fatal("pointer matches a changed file")
	}
	bst := &State{Kind: KindBundle, ExecSize: st.Size, ExecMtimeNs: st.MtimeUnixNs}
	if p.Matches(bst) || p.Matches(nil) {
		t.Fatal("file pointer matches a bundle")
	}
	if err := x.Point(file, e, bst); err == nil {
		t.Fatal("pointer of the wrong kind accepted")
	}

	// A bundle pointer checks the tree summary and the main executable.
	app := filepath.Join(t.TempDir(), "T.app")
	os.MkdirAll(filepath.Join(app, "Contents", "MacOS"), 0o755)
	os.WriteFile(filepath.Join(app, "Contents", "MacOS", "T"), []byte("exe"), 0o755)
	tree := bundleid.Summarize(app)
	be := NewEntry(bundleReport("T.app", digest("exe"), digest("fp"), time.Now()), app, "", "v", false)
	bst = &State{Kind: KindBundle, Tree: tree, ExecSize: 3, ExecMtimeNs: 42}
	if err := x.Put(be, Extra{}); err != nil {
		t.Fatal(err)
	}
	if err := x.Point(app, be, bst); err != nil {
		t.Fatal(err)
	}
	bp, err := x.Pointer(app)
	if err != nil || bp.Kind != KindBundle || !bp.Matches(bst) {
		t.Fatalf("bundle pointer %+v %v", bp, err)
	}
	b, _ = os.ReadFile(x.PointerPath(app))
	m = nil
	json.Unmarshal(b, &m)
	for _, k := range []string{"version", "entry", "kind", "tree_entries", "tree_size", "tree_mtime_unix_ns", "exec_size", "exec_mtime_unix_ns"} {
		if _, ok := m[k]; !ok {
			t.Errorf("bundle pointer lacks %s: %s", k, b)
		}
	}
	if len(m) != 8 {
		t.Errorf("bundle pointer %s", b)
	}
	changed := *bst
	changed.Tree.Entries++
	if bp.Matches(&changed) {
		t.Fatal("bundle pointer matches a changed tree")
	}
	changed = *bst
	changed.ExecMtimeNs++
	if bp.Matches(&changed) {
		t.Fatal("bundle pointer matches a changed main executable")
	}

	// Layout and permissions: hex names only, version 2 everywhere, no
	// temporary files left.
	for _, d := range []string{"", "entries", "paths", "content"} {
		d = filepath.Join(data, "index", d)
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
			if strings.HasSuffix(de.Name(), ".json") {
				b, _ := os.ReadFile(filepath.Join(d, de.Name()))
				var v struct{ Version int }
				if json.Unmarshal(b, &v) != nil || v.Version != 2 {
					t.Errorf("%s: %s", de.Name(), b)
				}
			}
		}
		if st, _ := os.Stat(d); runtime.GOOS != "windows" && st.Mode().Perm() != 0o755 {
			t.Errorf("%s mode %v", d, st.Mode())
		}
	}
	if des, _ := os.ReadDir(filepath.Join(data, "index")); len(des) != 3 {
		t.Errorf("top level holds %d entries, want the 3 directories", len(des))
	}

	// Invalid ids are refused, never used as names.
	bad := *e
	bad.EntryID = "../../etc/passwd"
	if err := x.Put(&bad, Extra{}); err == nil {
		t.Fatal("accepted a bad entry id")
	}
	bad = *e
	bad.ContentKey = "nothex"
	if err := x.Put(&bad, Extra{}); err == nil || x.SetContent(&bad) == nil {
		t.Fatal("accepted a bad content key")
	}
	bad = *e
	bad.Kind = "dir"
	if err := x.Put(&bad, Extra{}); err == nil {
		t.Fatal("accepted a bad kind")
	}
	if _, err := x.Get("../x"); err == nil {
		t.Fatal("Get accepted a bad id")
	}
	if _, err := x.Content("../x"); err == nil {
		t.Fatal("Content accepted a bad key")
	}
	// A symlinked entry is not read.
	if runtime.GOOS != "windows" {
		target := filepath.Join(t.TempDir(), "e.json")
		b, _ := os.ReadFile(x.EntryPath(e.EntryID))
		os.WriteFile(target, b, 0o644)
		os.Remove(x.EntryPath(e.EntryID))
		os.Symlink(target, x.EntryPath(e.EntryID))
		if _, err := x.Get(e.EntryID); err == nil {
			t.Fatal("followed a symlinked entry")
		}
	}
}

// Version 1 files are removed on Open; version 2 files and anything that
// is not an index file are kept.
func TestPurgeV1(t *testing.T) {
	data := t.TempDir()
	dir := filepath.Join(data, "index")
	os.MkdirAll(filepath.Join(dir, "paths"), 0o755)
	v1 := digest("v1")
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, v1+".json"), `{"version":1,"sha256":"`+v1+`"}`)
	write(filepath.Join(dir, v1+".html"), "<p>v1</p>")
	write(filepath.Join(dir, "notes.json"), "{}")
	write(filepath.Join(dir, "paths", digest("/old")+".json"), `{"sha256":"`+v1+`","size":1,"mtime_unix_ns":2}`)
	write(filepath.Join(dir, "paths", digest("/junk")+".json"), `not json`)
	keep := filepath.Join(dir, "paths", digest("/new")+".json")
	write(keep, `{"version":2,"entry":"`+v1+`","kind":"file","size":1,"mtime_unix_ns":2}`)
	x, err := Open(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{v1 + ".json", v1 + ".html", "paths/" + digest("/old") + ".json", "paths/" + digest("/junk") + ".json"} {
		if _, err := os.Lstat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Errorf("%s not removed", gone)
		}
	}
	for _, kept := range []string{keep, filepath.Join(dir, "notes.json")} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("%s removed", kept)
		}
	}
	if p, err := x.Pointer("/new"); err != nil || p.Entry != v1 {
		t.Fatalf("v2 pointer %+v %v", p, err)
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
	b, err := os.ReadFile(x.CardPath(e.EntryID))
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
		"s-critical", "Full report: binchk menu ▸ Recent reports", "prefers-color-scheme:dark",
		// The Quick Look extension puts its "matched by contents" banner
		// right after this element and styles it with .match.
		`<div class="card">`, ".match{"} {
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
	got, err := x.SetMarkedSafe(e.EntryID, true)
	if err != nil || !got.MarkedSafe {
		t.Fatalf("%+v %v", got, err)
	}
	b, _ = os.ReadFile(x.CardPath(e.EntryID))
	if !strings.Contains(string(b), "marked this file as safe") || !strings.Contains(string(b), "arm64e") {
		t.Fatalf("card after mark safe:\n%s", b)
	}
	if again, _ := x.Get(e.EntryID); !again.MarkedSafe {
		t.Fatal("marked_safe not stored")
	}
}

func TestRecentAndByTrust(t *testing.T) {
	x, _ := Open(t.TempDir())
	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	for i, name := range []string{"a", "b", "c", "d"} {
		// a and b share content, at different paths: two entries.
		key := digest(map[bool]string{true: "ab", false: name}[name == "a" || name == "b"])
		e := NewEntry(sampleReport(name, key, base.Add(time.Duration(i)*time.Minute)), "/d/"+name, "", "v", false)
		if err := x.Put(e, Extra{}); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(x.Dir(), "entries", "notes.json"), []byte("{}"), 0o644) // ignored: not a digest
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
	same, err := x.ByTrust(KindFile, digest("ab"))
	if err != nil || len(same) != 2 {
		t.Fatalf("by trust key: %+v %v", same, err)
	}
	// A bundle with the same fingerprint but other contents is not the same.
	br := bundleReport("T.app", digest("main"), digest("ab"), base)
	br.Hashes.BundleContents = digest("bundle contents")
	if err := x.Put(NewEntry(br, "/d/T.app", "", "v", false), Extra{}); err != nil {
		t.Fatal(err)
	}
	if same, _ := x.ByTrust(KindFile, digest("ab")); len(same) != 2 {
		t.Fatalf("by trust key after a bundle: %+v", same)
	}
	if same, _ := x.ByTrust(KindBundle, digest("ab")); len(same) != 0 {
		t.Fatalf("bundle found by its fingerprint: %+v", same)
	}
	if same, _ := x.ByTrust(KindBundle, digest("bundle contents")); len(same) != 1 || same[0].FileName != "T.app" {
		t.Fatalf("bundle by contents digest: %+v", same)
	}
	if _, err := x.ByTrust(KindBundle, ""); err == nil {
		t.Fatal("empty trust key accepted")
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
		r.Hashes.Bundle = sha
		r.Signature = analyze.Signature{}
		e := NewEntry(r, "/d/f", "/r/f.html", "v", false)
		if err := x.Put(e, Extra{}); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(x.CardPath(e.EntryID))
		card := string(b)
		if got := strings.Contains(card, "Not signed by an identified developer"); got != c.sign {
			t.Errorf("%s: signing line shown = %v, want %v", c.format, got, c.sign)
		}
		if got := strings.Contains(card, "otarized"); got != c.notary {
			t.Errorf("%s: notarization shown = %v, want %v", c.format, got, c.notary)
		}
	}
}
