// Package index keeps a content-addressed summary of every analysis so
// other programs (the Quick Look extension) can show a file's verdict
// without running binchk:
//
//	<data>/index/<sha256>.json        condensed result (Entry)
//	<data>/index/<sha256>.html        compact, self-contained HTML card
//	<data>/index/paths/<p>.json       Pointer for the path, p = sha256(path)
//
// <sha256> is the file's SHA-256 (an app bundle's main executable's). A
// pointer lets a reader skip hashing while the file's size and mtime still
// match. Every file is written atomically, and every name in the index is a
// hex digest, never anything taken from a file name.
package index

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/danczar/binchk/internal/analyze"
	"github.com/danczar/binchk/internal/report"
)

// SchemaVersion is Entry.Version.
const SchemaVersion = 1

// MaxTopFindings bounds Entry.TopFindings.
const MaxTopFindings = 5

// Finding is a condensed finding.
type Finding struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
}

// Entry is <sha256>.json.
type Entry struct {
	Version       int       `json:"version"`
	SHA256        string    `json:"sha256"`
	FileName      string    `json:"file_name"`
	Path          string    `json:"path"`
	Format        string    `json:"format"`
	Verdict       string    `json:"verdict"`
	Score         int       `json:"score"`
	Summary       string    `json:"summary"`
	Signer        string    `json:"signer"`
	Notarized     bool      `json:"notarized"`
	Gatekeeper    string    `json:"gatekeeper"`
	TopFindings   []Finding `json:"top_findings"`
	ReportPath    string    `json:"report_path"`
	AnalyzedAt    string    `json:"analyzed_at"` // RFC 3339, UTC
	MarkedSafe    bool      `json:"marked_safe"`
	BinchkVersion string    `json:"binchk_version"`
}

// Time parses AnalyzedAt (zero if malformed).
func (e *Entry) Time() time.Time {
	t, _ := time.Parse(time.RFC3339, e.AnalyzedAt)
	return t
}

// Pointer is paths/<sha256(path)>.json.
type Pointer struct {
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	MtimeUnixNs int64  `json:"mtime_unix_ns"`
}

// Matches reports whether st (the file, or a bundle's main executable) is
// still the state the pointer was recorded for.
func (p *Pointer) Matches(st fs.FileInfo) bool {
	return st != nil && p.Size == st.Size() && p.MtimeUnixNs == st.ModTime().UnixNano()
}

// NewEntry condenses r, the analysis of the file at path.
func NewEntry(r *analyze.Report, path, reportPath, version string, markedSafe bool) *Entry {
	e := &Entry{
		Version: SchemaVersion, SHA256: strings.ToLower(r.Hashes.SHA256), FileName: r.FileName, Path: path,
		Format: r.Format, Verdict: string(r.Verdict), Score: r.Score, Summary: r.Summary,
		Signer: r.Signature.Signer, Notarized: r.Signature.Notarized, Gatekeeper: r.Signature.Gatekeeper,
		TopFindings: TopFindings(r.Findings), ReportPath: reportPath, MarkedSafe: markedSafe,
		BinchkVersion: version,
	}
	if e.FileName == "" {
		e.FileName = filepath.Base(path)
	}
	at := r.AnalyzedAt
	if at.IsZero() {
		at = time.Now()
	}
	e.AnalyzedAt = at.UTC().Format(time.RFC3339)
	return e
}

// TopFindings returns the most severe findings, at most MaxTopFindings,
// keeping the analyser's order among equals.
func TopFindings(fs []analyze.Finding) []Finding {
	sorted := slices.Clone(fs)
	slices.SortStableFunc(sorted, func(a, b analyze.Finding) int { return int(b.Severity) - int(a.Severity) })
	out := []Finding{}
	for _, f := range sorted {
		if len(out) == MaxTopFindings {
			break
		}
		out = append(out, Finding{Severity: f.Severity.String(), Title: f.Title})
	}
	return out
}

// Index is the on-disk index under a data directory.
type Index struct {
	dir string
}

// Open creates <dataDir>/index (and its paths/ directory) if needed.
func Open(dataDir string) (*Index, error) {
	x := &Index{dir: filepath.Join(dataDir, "index")}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	for _, d := range []string{x.dir, x.pathsDir()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
		if err := os.Chmod(d, 0o755); err != nil {
			return nil, err
		}
	}
	return x, nil
}

func (x *Index) Dir() string      { return x.dir }
func (x *Index) pathsDir() string { return filepath.Join(x.dir, "paths") }

// IsDigest reports whether s is a lowercase hex SHA-256.
func IsDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// PathKey is the pointer name for path: the hex SHA-256 of its UTF-8 bytes.
func PathKey(path string) string {
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:])
}

// EntryPath, CardPath and PointerPath are where the files for a digest or
// path live.
func (x *Index) EntryPath(sha string) string { return filepath.Join(x.dir, sha+".json") }
func (x *Index) CardPath(sha string) string  { return filepath.Join(x.dir, sha+".html") }
func (x *Index) PointerPath(path string) string {
	return filepath.Join(x.pathsDir(), PathKey(path)+".json")
}

// Extra is what the card shows beyond the entry.
type Extra struct {
	Arches []string
	Size   int64
}

// Put writes e and its card. The card is written first, so a reader that
// finds the entry also finds a card at least as new.
func (x *Index) Put(e *Entry, extra Extra) error {
	if !IsDigest(e.SHA256) {
		return fmt.Errorf("index: invalid sha256 %q", e.SHA256)
	}
	if e.TopFindings == nil {
		e.TopFindings = []Finding{}
	}
	var card bytes.Buffer
	if err := report.WriteCard(&card, cardData(e, extra)); err != nil {
		return err
	}
	if err := writeAtomic(x.CardPath(e.SHA256), card.Bytes()); err != nil {
		return err
	}
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(x.EntryPath(e.SHA256), append(b, '\n'))
}

// Point records that path (absolute, as analysed) has digest sha while its
// identity file has state st.
func (x *Index) Point(path, sha string, st fs.FileInfo) error {
	if !IsDigest(sha) {
		return fmt.Errorf("index: invalid sha256 %q", sha)
	}
	if !filepath.IsAbs(path) || st == nil {
		return errors.New("index: pointer needs an absolute path and its state")
	}
	b, err := json.Marshal(Pointer{SHA256: sha, Size: st.Size(), MtimeUnixNs: st.ModTime().UnixNano()})
	if err != nil {
		return err
	}
	return writeAtomic(x.PointerPath(path), append(b, '\n'))
}

// Pointer reads the pointer for path, if any.
func (x *Index) Pointer(path string) (*Pointer, error) {
	b, err := os.ReadFile(x.PointerPath(path))
	if err != nil {
		return nil, err
	}
	var p Pointer
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	if !IsDigest(p.SHA256) {
		return nil, fmt.Errorf("index: bad pointer for %s", path)
	}
	return &p, nil
}

// Get reads the entry for sha.
func (x *Index) Get(sha string) (*Entry, error) {
	if !IsDigest(sha) {
		return nil, fmt.Errorf("index: invalid sha256 %q", sha)
	}
	b, err := os.ReadFile(x.EntryPath(sha))
	if err != nil {
		return nil, err
	}
	var e Entry
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// SetMarkedSafe updates the entry's marked_safe flag and re-renders its card.
func (x *Index) SetMarkedSafe(sha string, safe bool) (*Entry, error) {
	e, err := x.Get(sha)
	if err != nil {
		return nil, err
	}
	e.MarkedSafe = safe
	return e, x.Put(e, extraFromReport(e.ReportPath))
}

// extraFromReport recovers the card's extra details from the full JSON
// report next to the HTML one, when there is one.
func extraFromReport(htmlPath string) Extra {
	if !strings.HasSuffix(htmlPath, ".html") {
		return Extra{}
	}
	b, err := os.ReadFile(strings.TrimSuffix(htmlPath, ".html") + ".json")
	if err != nil {
		return Extra{}
	}
	var r struct {
		Arches []string `json:"arches"`
		Size   int64    `json:"size"`
	}
	if json.Unmarshal(b, &r) != nil {
		return Extra{}
	}
	return Extra{Arches: r.Arches, Size: r.Size}
}

// Recent returns up to n entries analysed after since, newest first.
func (x *Index) Recent(n int, since time.Time) ([]*Entry, error) {
	des, err := os.ReadDir(x.dir)
	if err != nil {
		return nil, err
	}
	var out []*Entry
	for _, de := range des {
		name := de.Name()
		sha, ok := strings.CutSuffix(name, ".json")
		if !ok || !IsDigest(sha) || !de.Type().IsRegular() {
			continue
		}
		e, err := x.Get(sha)
		if err != nil || e.SHA256 != sha || !e.Time().After(since) {
			continue
		}
		out = append(out, e)
	}
	SortNewest(out)
	if len(out) > n {
		out = out[:n]
	}
	return out, nil
}

// SortNewest orders entries by analysis time, newest first.
func SortNewest(es []*Entry) {
	slices.SortStableFunc(es, func(a, b *Entry) int { return b.Time().Compare(a.Time()) })
}

var severities = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}

func cardData(e *Entry, extra Extra) *report.CardData {
	c := &report.CardData{
		FileName: e.FileName, Path: e.Path, Format: e.Format, Arches: extra.Arches, Size: extra.Size,
		Verdict: e.Verdict, Score: e.Score, Summary: e.Summary, Signer: e.Signer, Notarized: e.Notarized,
		Gatekeeper: e.Gatekeeper, AnalyzedAt: e.Time(), MarkedSafe: e.MarkedSafe, Version: e.BinchkVersion,
	}
	for _, f := range e.TopFindings {
		sev := f.Severity
		if !severities[sev] {
			sev = "info"
		}
		c.Findings = append(c.Findings, report.CardFinding{Severity: sev, Title: f.Title})
	}
	return c
}

// writeAtomic replaces path with b (mode 0644) via a temporary file in the
// same directory and a rename.
func writeAtomic(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(0o644)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}
