// Package index keeps a summary of every analysis so other programs (the
// Quick Look extension) can show an item's verdict without running binchk.
// Schema version 2:
//
//	<data>/index/entries/<id>.json   condensed result (Entry)
//	<data>/index/entries/<id>.html   compact, self-contained HTML card
//	<data>/index/paths/<p>.json      Pointer: the entry last recorded for a path
//	<data>/index/content/<k>.json    ContentRef: the latest analysis of content k
//
// An item's content key k is its file's SHA-256, or for an app bundle its
// bundle fingerprint (internal/bundleid). An entry is one analysis of one
// item: id = SHA-256("v2\x00" + absolute path + "\x00" + k), so analysing
// the same path and content again replaces the entry, and different items
// never share one. p is the SHA-256 of the path's UTF-8 bytes.
//
// An entry also records its trust key (Entry.TrustKey): what the allowlist
// and Mark as safe use. For a file it is the content key; for a bundle it is
// the bundle contents digest, which, unlike the fingerprint, covers every
// byte of every file in it. Readers do not use it.
//
// A reader finds the entry for an item through its path pointer while the
// pointer's staleness data still matches the item; otherwise it computes
// the content key and falls back to the content map, which names the most
// recent analysis of the same content, possibly at another path. Every file
// is written atomically, every name is a hex digest, and every JSON file
// carries "version": 2.
package index

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/danczar/binchk/internal/analyze"
	"github.com/danczar/binchk/internal/bundleid"
	"github.com/danczar/binchk/internal/report"
)

// SchemaVersion is the "version" of every JSON file in the index.
const SchemaVersion = 2

// Kinds of indexed items.
const (
	KindFile   = "file"
	KindBundle = "bundle"
)

// MaxTopFindings bounds Entry.TopFindings.
const MaxTopFindings = 5

// maxJSON bounds the index's own JSON files when they are read back.
const maxJSON = 1 << 20

// Finding is a condensed finding.
type Finding struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
}

// Entry is entries/<id>.json.
type Entry struct {
	Version    int    `json:"version"`
	EntryID    string `json:"entry_id"`
	ContentKey string `json:"content_key"`
	// TrustKey is r.TrustKey(): the file's SHA-256, or the bundle contents
	// digest ("" when binchk could not read the whole bundle).
	TrustKey string `json:"trust_key"`
	Kind     string `json:"kind"`
	// SHA256 is the file's SHA-256; for a bundle, its main executable's.
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
	// Paths are every absolute spelling this entry was recorded at: the
	// analysed path, and the same item through its folder's real path.
	Paths []string `json:"paths"`
}

// Time parses AnalyzedAt (zero if malformed).
func (e *Entry) Time() time.Time {
	t, _ := time.Parse(time.RFC3339, e.AnalyzedAt)
	return t
}

// EntryID is the entry name for content key key analysed at path.
func EntryID(path, key string) string {
	sum := sha256.Sum256([]byte("v2\x00" + path + "\x00" + key))
	return hex.EncodeToString(sum[:])
}

// State is what a path pointer checks to tell that an item is unchanged
// since it was analysed: a file's size and mtime, or a bundle's tree
// summary and its main executable's size and mtime.
type State struct {
	Kind        string
	Size        int64 // file
	MtimeUnixNs int64 // file
	Tree        bundleid.Tree
	ExecSize    int64
	ExecMtimeNs int64
}

// Pointer is paths/<sha256(path)>.json. Only the fields of its kind are
// present.
type Pointer struct {
	Version         int    `json:"version"`
	Entry           string `json:"entry"`
	Kind            string `json:"kind"`
	Size            *int64 `json:"size,omitempty"`
	MtimeUnixNs     *int64 `json:"mtime_unix_ns,omitempty"`
	TreeEntries     *int64 `json:"tree_entries,omitempty"`
	TreeSize        *int64 `json:"tree_size,omitempty"`
	TreeMtimeUnixNs *int64 `json:"tree_mtime_unix_ns,omitempty"`
	ExecSize        *int64 `json:"exec_size,omitempty"`
	ExecMtimeUnixNs *int64 `json:"exec_mtime_unix_ns,omitempty"`
}

func newPointer(entry string, st *State) *Pointer {
	v := func(n int64) *int64 { return &n }
	p := &Pointer{Version: SchemaVersion, Entry: entry, Kind: st.Kind}
	if st.Kind == KindBundle {
		p.TreeEntries, p.TreeSize, p.TreeMtimeUnixNs = v(st.Tree.Entries), v(st.Tree.Size), v(st.Tree.MtimeUnixNs)
		p.ExecSize, p.ExecMtimeUnixNs = v(st.ExecSize), v(st.ExecMtimeNs)
	} else {
		p.Size, p.MtimeUnixNs = v(st.Size), v(st.MtimeUnixNs)
	}
	return p
}

// Matches reports whether st is still the state the pointer was recorded
// for.
func (p *Pointer) Matches(st *State) bool {
	eq := func(a *int64, b int64) bool { return a != nil && *a == b }
	switch {
	case st == nil || p.Kind != st.Kind:
		return false
	case st.Kind == KindBundle:
		return eq(p.TreeEntries, st.Tree.Entries) && eq(p.TreeSize, st.Tree.Size) && eq(p.TreeMtimeUnixNs, st.Tree.MtimeUnixNs) &&
			eq(p.ExecSize, st.ExecSize) && eq(p.ExecMtimeUnixNs, st.ExecMtimeNs)
	default:
		return eq(p.Size, st.Size) && eq(p.MtimeUnixNs, st.MtimeUnixNs)
	}
}

// ContentRef is content/<key>.json: the most recent analysis of the
// content.
type ContentRef struct {
	Version    int    `json:"version"`
	Entry      string `json:"entry"`
	Path       string `json:"path"`
	AnalyzedAt string `json:"analyzed_at"`
}

// NewEntry condenses r, the analysis of the item at path. Its content key
// is r.ContentKey(); without one the entry has no id and is not stored.
func NewEntry(r *analyze.Report, path, reportPath, version string, markedSafe bool) *Entry {
	e := &Entry{
		Version: SchemaVersion, ContentKey: strings.ToLower(r.ContentKey()), TrustKey: strings.ToLower(r.TrustKey()), Kind: KindFile,
		SHA256: strings.ToLower(r.Hashes.SHA256), FileName: r.FileName, Path: path,
		Format: r.Format, Verdict: string(r.Verdict), Score: r.Score, Summary: r.Summary,
		Signer: r.Signature.Signer, Notarized: r.Signature.Notarized, Gatekeeper: r.Signature.Gatekeeper,
		TopFindings: TopFindings(r.Findings), ReportPath: reportPath, MarkedSafe: markedSafe,
		BinchkVersion: version, Paths: []string{path},
	}
	if r.IsBundle() {
		e.Kind = KindBundle
	}
	if IsDigest(e.ContentKey) {
		e.EntryID = EntryID(path, e.ContentKey)
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

// Open creates <dataDir>/index and its directories if needed, and removes
// what an older schema left there.
func Open(dataDir string) (*Index, error) {
	x := &Index{dir: filepath.Join(dataDir, "index")}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	for _, d := range []string{x.dir, x.entriesDir(), x.pathsDir(), x.contentDir()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
		if err := os.Chmod(d, 0o755); err != nil {
			return nil, err
		}
	}
	x.purgeV1()
	return x, nil
}

func (x *Index) Dir() string                { return x.dir }
func (x *Index) entriesDir() string         { return filepath.Join(x.dir, "entries") }
func (x *Index) pathsDir() string           { return filepath.Join(x.dir, "paths") }
func (x *Index) contentDir() string         { return filepath.Join(x.dir, "content") }
func (x *Index) EntryPath(id string) string { return filepath.Join(x.entriesDir(), id+".json") }
func (x *Index) CardPath(id string) string  { return filepath.Join(x.entriesDir(), id+".html") }
func (x *Index) ContentPath(key string) string {
	return filepath.Join(x.contentDir(), key+".json")
}
func (x *Index) PointerPath(path string) string {
	return filepath.Join(x.pathsDir(), PathKey(path)+".json")
}

// purgeV1 removes schema 1 files: <sha256>.json/.html at the top level and
// path pointers without "version": 2. Version 1 was never released, so they
// are dropped rather than migrated.
func (x *Index) purgeV1() {
	if des, err := os.ReadDir(x.dir); err == nil {
		for _, de := range des {
			name := de.Name()
			stem, ext := strings.TrimSuffix(name, filepath.Ext(name)), filepath.Ext(name)
			if de.Type().IsRegular() && IsDigest(stem) && (ext == ".json" || ext == ".html") {
				os.Remove(filepath.Join(x.dir, name))
			}
		}
	}
	if des, err := os.ReadDir(x.pathsDir()); err == nil {
		for _, de := range des {
			name := de.Name()
			if stem, ok := strings.CutSuffix(name, ".json"); !ok || !IsDigest(stem) || !de.Type().IsRegular() {
				continue
			}
			p := filepath.Join(x.pathsDir(), name)
			var v struct {
				Version int `json:"version"`
			}
			if b, err := readSmall(p); err != nil || json.Unmarshal(b, &v) != nil || v.Version != SchemaVersion {
				os.Remove(p)
			}
		}
	}
}

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

// Extra is what the card shows beyond the entry.
type Extra struct {
	Arches []string
	Size   int64
}

func (e *Entry) valid() error {
	switch {
	case !IsDigest(e.EntryID) || !IsDigest(e.ContentKey):
		return fmt.Errorf("index: entry %q has no valid id or content key", e.EntryID)
	case e.Kind != KindFile && e.Kind != KindBundle:
		return fmt.Errorf("index: entry %s has kind %q", e.EntryID, e.Kind)
	}
	return nil
}

// Put writes e and its card. The card is written first, so a reader that
// finds the entry also finds a card at least as new.
func (x *Index) Put(e *Entry, extra Extra) error {
	if err := e.valid(); err != nil {
		return err
	}
	e.Version = SchemaVersion
	if e.TopFindings == nil {
		e.TopFindings = []Finding{}
	}
	if e.Paths == nil {
		e.Paths = []string{}
	}
	var card bytes.Buffer
	if err := report.WriteCard(&card, cardData(e, extra)); err != nil {
		return err
	}
	if err := writeAtomic(x.CardPath(e.EntryID), card.Bytes()); err != nil {
		return err
	}
	return writeJSON(x.EntryPath(e.EntryID), e)
}

// Point records that path (absolute) last held entry e, while the item was
// in state st.
func (x *Index) Point(path string, e *Entry, st *State) error {
	if err := e.valid(); err != nil {
		return err
	}
	if !filepath.IsAbs(path) || st == nil || st.Kind != e.Kind {
		return errors.New("index: pointer needs an absolute path and the item's state")
	}
	return writeJSON(x.PointerPath(path), newPointer(e.EntryID, st))
}

// SetContent records e as the most recent analysis of its content.
func (x *Index) SetContent(e *Entry) error {
	if err := e.valid(); err != nil {
		return err
	}
	return writeJSON(x.ContentPath(e.ContentKey), &ContentRef{
		Version: SchemaVersion, Entry: e.EntryID, Path: e.Path, AnalyzedAt: e.AnalyzedAt,
	})
}

// Pointer reads the pointer for path, if any.
func (x *Index) Pointer(path string) (*Pointer, error) {
	var p Pointer
	if err := readJSON(x.PointerPath(path), &p); err != nil {
		return nil, err
	}
	if p.Version != SchemaVersion || !IsDigest(p.Entry) {
		return nil, fmt.Errorf("index: bad pointer for %s", path)
	}
	return &p, nil
}

// Content reads the content map entry for key, if any.
func (x *Index) Content(key string) (*ContentRef, error) {
	if !IsDigest(key) {
		return nil, fmt.Errorf("index: invalid content key %q", key)
	}
	var c ContentRef
	if err := readJSON(x.ContentPath(key), &c); err != nil {
		return nil, err
	}
	if c.Version != SchemaVersion || !IsDigest(c.Entry) {
		return nil, fmt.Errorf("index: bad content map for %s", key)
	}
	return &c, nil
}

// Get reads the entry with id.
func (x *Index) Get(id string) (*Entry, error) {
	if !IsDigest(id) {
		return nil, fmt.Errorf("index: invalid entry id %q", id)
	}
	var e Entry
	if err := readJSON(x.EntryPath(id), &e); err != nil {
		return nil, err
	}
	if e.Version != SchemaVersion || e.EntryID != id {
		return nil, fmt.Errorf("index: bad entry %s", id)
	}
	return &e, nil
}

// SetMarkedSafe updates the entry's marked_safe flag and re-renders its card.
func (x *Index) SetMarkedSafe(id string, safe bool) (*Entry, error) {
	e, err := x.Get(id)
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

// All returns every entry, in no particular order.
func (x *Index) All() ([]*Entry, error) {
	des, err := os.ReadDir(x.entriesDir())
	if err != nil {
		return nil, err
	}
	var out []*Entry
	for _, de := range des {
		id, ok := strings.CutSuffix(de.Name(), ".json")
		if !ok || !IsDigest(id) || !de.Type().IsRegular() {
			continue
		}
		if e, err := x.Get(id); err == nil {
			out = append(out, e)
		}
	}
	return out, nil
}

// ByTrust returns every entry of kind whose trust key is key.
func (x *Index) ByTrust(kind, key string) ([]*Entry, error) {
	if !IsDigest(key) {
		return nil, fmt.Errorf("index: invalid trust key %q", key)
	}
	return x.filter(func(e *Entry) bool { return e.Kind == kind && e.TrustKey == key })
}

func (x *Index) filter(keep func(*Entry) bool) ([]*Entry, error) {
	all, err := x.All()
	if err != nil {
		return nil, err
	}
	var out []*Entry
	for _, e := range all {
		if keep(e) {
			out = append(out, e)
		}
	}
	return out, nil
}

// Recent returns up to n entries analysed after since, newest first.
func (x *Index) Recent(n int, since time.Time) ([]*Entry, error) {
	all, err := x.All()
	if err != nil {
		return nil, err
	}
	var out []*Entry
	for _, e := range all {
		if e.Time().After(since) {
			out = append(out, e)
		}
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

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(b, '\n'))
}

// readSmall reads a regular file of at most maxJSON bytes, without
// following a symbolic link in its last component.
func readSmall(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > maxJSON {
		return nil, fmt.Errorf("index: %s is not a small regular file", path)
	}
	return os.ReadFile(path)
}

func readJSON(path string, v any) error {
	b, err := readSmall(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
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
