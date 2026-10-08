// Package app ties the pipeline together: watcher -> analysis (in place) ->
// report + index -> Finder tag -> notification. The tray and headless
// modes both drive it.
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/danczar/binchk/internal/analyze"
	"github.com/danczar/binchk/internal/config"
	"github.com/danczar/binchk/internal/container"
	"github.com/danczar/binchk/internal/detect"
	"github.com/danczar/binchk/internal/index"
	"github.com/danczar/binchk/internal/legacy"
	"github.com/danczar/binchk/internal/notify"
	"github.com/danczar/binchk/internal/provenance"
	"github.com/danczar/binchk/internal/report"
	"github.com/danczar/binchk/internal/watcher"
)

// EventKind describes a state change the UI should reflect.
type EventKind int

const (
	ScanStarted EventKind = iota
	ScanFinished
	ItemsChanged
	ScanFailed
)

type Event struct {
	Kind  EventKind
	Path  string
	Entry *index.Entry
	Err   error
}

// recentCap bounds the in-memory list of recent reports.
const recentCap = 50

type App struct {
	cfg        *config.Config
	eng        *analyze.Engine
	rec        *Recorder
	reportsDir string
	dataDir    string
	Log        *log.Logger

	// notifier shows a desktop notification (replaceable in tests).
	notifier func(title, body, openPath string, u notify.Urgency)

	mu        sync.Mutex
	recent    []*index.Entry // newest first, analysed after clearedAt
	clearedAt time.Time
	latest    *index.Entry // most recently analysed file
	scanning  map[string]bool
	paused    bool
	listeners []func(Event)
	sem       chan struct{}
	cancel    context.CancelFunc
}

// NewEngine builds an analysis engine from config (rules, hash lists).
func NewEngine(cfg *config.Config) (*analyze.Engine, error) {
	eng, _, err := newEngine(cfg)
	return eng, err
}

// NewEngineAllow is NewEngine that also returns the allowlist it uses.
func NewEngineAllow(cfg *config.Config) (*analyze.Engine, *analyze.HashList, error) {
	return newEngine(cfg)
}

func newEngine(cfg *config.Config) (*analyze.Engine, *analyze.HashList, error) {
	var extra []analyze.Rule
	if p := cfg.Resolve(cfg.RulesFile); p != "" {
		rules, err := analyze.LoadRules(p)
		switch {
		case err == nil:
			extra = rules
		case !errors.Is(err, os.ErrNotExist):
			return nil, nil, fmt.Errorf("rules: %w", err)
		}
	}
	allow := analyze.LoadHashList(cfg.Resolve(cfg.AllowlistFile))
	eng, err := analyze.NewEngine(analyze.Options{
		Budget:           time.Duration(cfg.AnalysisBudget),
		ExtraRules:       extra,
		Blocklist:        analyze.LoadHashList(cfg.Resolve(cfg.BlocklistFile)),
		Allowlist:        allow,
		VerifySignatures: cfg.VerifySignatures,
		Workers:          runtime.NumCPU(),
	})
	return eng, allow, err
}

// New prepares the app; version is recorded in index entries.
func New(cfg *config.Config, logToFile bool, version string) (*App, error) {
	data := cfg.DataPath()
	if err := os.MkdirAll(data, 0o700); err != nil {
		return nil, err
	}
	var w io.Writer = os.Stdout
	if logToFile {
		f, err := os.OpenFile(filepath.Join(data, "binchk.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		w = f
	}
	lg := log.New(w, "", log.LstdFlags)
	eng, allow, err := newEngine(cfg)
	if err != nil {
		return nil, err
	}
	idx, err := index.Open(data)
	if err != nil {
		return nil, err
	}
	a := &App{
		cfg: cfg, eng: eng, dataDir: data, Log: lg,
		rec:        &Recorder{Index: idx, Config: cfg, Allow: allow, Version: version},
		reportsDir: filepath.Join(data, "reports"),
		notifier:   notify.Show,
		scanning:   map[string]bool{},
		sem:        make(chan struct{}, cfg.ConcurrentScans),
	}
	a.clearedAt = a.loadState().RecentClearedAt
	a.recent, _ = idx.Recent(recentCap, a.clearedAt)
	if len(a.recent) > 0 {
		a.latest = a.recent[0]
	}
	return a, nil
}

func (a *App) Config() *config.Config { return a.cfg }
func (a *App) DataDir() string        { return a.dataDir }
func (a *App) ReportsDir() string     { return a.reportsDir }
func (a *App) Index() *index.Index    { return a.rec.Index }

// Subscribe registers fn for UI events. fn is called from worker goroutines.
func (a *App) Subscribe(fn func(Event)) {
	a.mu.Lock()
	a.listeners = append(a.listeners, fn)
	a.mu.Unlock()
}

func (a *App) emit(ev Event) {
	a.mu.Lock()
	ls := append([]func(Event){}, a.listeners...)
	a.mu.Unlock()
	for _, fn := range ls {
		fn(ev)
	}
}

// Start begins watching. It returns once the watches are established.
//
// Items left in a v0.1.x quarantine vault are first returned to their
// original folders, before the watcher records what is already there, and
// are then analysed in place explicitly.
func (a *App) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	restored, err := legacy.Migrate(a.dataDir, a.Log)
	if err != nil {
		a.Log.Printf("legacy migration incomplete: %v", err)
	}
	w, err := watcher.New(a.cfg.WatchDirs, time.Duration(a.cfg.SettleDelay), a.cfg.IgnoreExtensions, a.isOwnPath, a.Log)
	if err != nil {
		return err
	}
	go w.Run(ctx)
	go func() {
		for f := range w.Found() {
			if a.Paused() || !a.wants(f.Format) {
				continue
			}
			go a.Handle(f.Path, f.At)
		}
	}()
	a.Log.Printf("binchk started; data in %s", a.dataDir)
	if len(restored) > 0 {
		a.announceMigration(restored)
		for _, r := range restored {
			if f := detect.SniffPath(r.To); f != detect.Unknown && a.wants(f) {
				go a.Handle(r.To, time.Now())
			}
		}
	}
	return nil
}

// wants reports whether files of format f are analysed here. Disk images,
// installers and apps only matter where they can run, and are only opened
// when enabled.
func (a *App) wants(f detect.Format) bool {
	return !f.IsContainer() || (runtime.GOOS == "darwin" && a.cfg.InspectInstallers && container.Supported(f))
}

func (a *App) announceMigration(rs []legacy.Restored) {
	msg := fmt.Sprintf("%d files were returned to their original folders.", len(rs))
	if len(rs) == 1 {
		msg = "1 file was returned to its original folder."
	}
	a.Log.Printf("binchk no longer quarantines downloads; %s", msg)
	if a.cfg.Notifications {
		a.notifier("binchk no longer quarantines downloads", msg, "", notify.Normal)
	}
}

func (a *App) Stop() {
	if a.cancel != nil {
		a.cancel()
	}
}

func (a *App) isOwnPath(p string) bool {
	return p == a.dataDir || strings.HasPrefix(p, a.dataDir+string(filepath.Separator))
}

func (a *App) SetPaused(p bool) {
	a.mu.Lock()
	a.paused = p
	a.mu.Unlock()
	a.emit(Event{Kind: ItemsChanged})
}

func (a *App) Paused() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.paused
}

// Recent returns recent reports (not cleared from the menu), newest first.
func (a *App) Recent() []*index.Entry {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*index.Entry, len(a.recent))
	for i, e := range a.recent {
		c := *e
		out[i] = &c
	}
	return out
}

// Latest is the most recently analysed file, if any.
func (a *App) Latest() *index.Entry {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.latest == nil {
		return nil
	}
	c := *a.latest
	return &c
}

func (a *App) Scanning() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.scanning)
}

func newID() string {
	var b [4]byte
	rand.Read(b[:])
	return time.Now().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}

// Handle analyses one detected file where it is, then reports, indexes,
// tags and notifies.
func (a *App) Handle(path string, detectedAt time.Time) {
	a.mu.Lock()
	if a.scanning[path] {
		a.mu.Unlock()
		return
	}
	a.scanning[path] = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.scanning, path)
		a.mu.Unlock()
		a.emit(Event{Kind: ItemsChanged})
	}()

	if st, err := os.Stat(path); err != nil {
		return // gone already
	} else if !st.IsDir() && a.cfg.MaxFileSize > 0 && st.Size() > a.cfg.MaxFileSize {
		a.Log.Printf("skip %s: %d bytes exceeds max_file_size", path, st.Size())
		return
	}
	a.emit(Event{Kind: ScanStarted, Path: path})

	// The item's state before analysis: if it changes meanwhile, the
	// pointer will not match and a reader computes the content key instead.
	idSt, idErr := IdentityState(path)
	id := newID()
	a.sem <- struct{}{}
	r := container.AnalyzeWith(context.Background(), a.eng, path, analyze.Meta{
		ID: id, FileName: filepath.Base(path), OriginalPath: path, Provenance: provenance.Read(path), DetectedAt: detectedAt,
	}, container.Options{MountImages: a.cfg.InspectInstallers})
	<-a.sem
	r.Latency = time.Since(detectedAt)
	reportPath := filepath.Join(a.reportsDir, id+".html")
	if err := report.Write(r, reportPath); err != nil {
		a.Log.Printf("report %s: %v", id, err)
		a.emit(Event{Kind: ScanFailed, Path: path, Err: err})
		return
	}
	if err := report.WriteJSON(r, filepath.Join(a.reportsDir, id+".json")); err != nil {
		a.Log.Printf("report %s: %v", id, err)
	}
	if idErr != nil {
		idSt = nil
	}
	e, err := a.rec.Record(r, path, reportPath, idSt)
	if err != nil {
		a.Log.Printf("index %s: %v", path, err)
	}
	a.Log.Printf("%s %s score=%d in %s (latency %s): %s", r.Verdict, path, r.Score,
		r.Elapsed.Round(time.Millisecond), r.Latency.Round(time.Millisecond), r.Summary)

	a.mu.Lock()
	a.latest = e
	a.recent = insertRecent(a.recent, e)
	a.mu.Unlock()
	ec := *e // listeners get their own copy; MarkSafe updates e
	a.emit(Event{Kind: ScanFinished, Path: path, Entry: &ec})
	if !e.MarkedSafe && a.cfg.Notifies(e.Verdict) {
		a.notify(e, r)
	}
}

// insertRecent puts e first, dropping an older result for the same entry
// (the same path and content; for results without a content key, the same
// path).
func insertRecent(list []*index.Entry, e *index.Entry) []*index.Entry {
	out := make([]*index.Entry, 0, len(list)+1)
	out = append(out, e)
	for _, o := range list {
		if (e.EntryID != "" && o.EntryID == e.EntryID) || (e.EntryID == "" && o.EntryID == "" && o.Path == e.Path) {
			continue
		}
		out = append(out, o)
	}
	if len(out) > recentCap {
		out = out[:recentCap]
	}
	return out
}

func (a *App) notify(e *index.Entry, r *analyze.Report) {
	title := fmt.Sprintf("%s: %s", e.Verdict, e.FileName)
	body := NotificationBody(r)
	u := notify.Normal
	if e.Verdict == string(analyze.VerdictMalicious) {
		u = notify.Critical
	}
	a.notifier(title, body, e.ReportPath, u)
}

// NotificationBody says what stood out, without promising that clicking
// the notification does anything (it cannot on every platform).
func NotificationBody(r *analyze.Report) string {
	counts := map[analyze.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, sev := range []analyze.Severity{analyze.Critical, analyze.High, analyze.Medium} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
		if len(parts) == 2 {
			break
		}
	}
	what := fmt.Sprintf("Risk %d/100", r.Score)
	if len(parts) > 0 {
		n := counts[analyze.Critical] + counts[analyze.High] + counts[analyze.Medium]
		what = strings.Join(parts, ", ") + " finding"
		if n != 1 {
			what += "s"
		}
	}
	if r.Verdict == analyze.VerdictError {
		what = r.Summary
	}
	return what + ". Open binchk ▸ Recent reports."
}

// MarkSafe trusts the content of the entry with id: its trust key (a
// file's SHA-256, or an app bundle's contents digest, which covers every
// byte in the bundle; never its main executable or its size-only
// fingerprint) joins the allowlist. Every entry with that trust key is
// marked safe and its card re-rendered, and binchk's Finder tag comes off
// every path those entries were recorded at that still holds exactly that
// content.
func (a *App) MarkSafe(id string) error { return a.MarkSafeAs(id, "") }

// MarkSafeAs is MarkSafe for an entry the user saw with trust key want. An
// item re-analysed in place keeps its entry ID, so if the contents changed
// between building the menu and the click, the swapped-in contents must not
// be trusted on the strength of the old report. An empty want skips the check.
func (a *App) MarkSafeAs(id, want string) error {
	if !index.IsDigest(id) {
		return errors.New("no index entry to mark as safe")
	}
	e, err := a.rec.Index.Get(id)
	if err != nil {
		return err
	}
	if want != "" && e.TrustKey != want {
		return errors.New("this item changed and was analysed again since the menu was shown; check its new report before marking it as safe")
	}
	key := e.TrustKey
	if !index.IsDigest(key) {
		if e.Kind == index.KindBundle {
			return errors.New("this app bundle's contents were not fully hashed (it is very large or was changing); run binchk scan on it, then mark it as safe")
		}
		return errors.New("no content hash to mark as safe")
	}
	note := "marked safe: " + e.FileName
	if e.Kind == index.KindBundle {
		note += " (app bundle contents)"
	}
	if err := a.rec.Allow.Add(key, note); err != nil {
		return fmt.Errorf("allowlist: %w", err)
	}
	same, err := a.rec.Index.ByTrust(e.Kind, key)
	if err != nil {
		return err
	}
	var errs []error
	var done []os.FileInfo // items already checked, under any spelling
	for _, s := range same {
		if _, err := a.rec.Index.SetMarkedSafe(s.EntryID, true); err != nil {
			errs = append(errs, err)
		}
		for _, p := range s.Paths {
			st, err := os.Lstat(p)
			if err != nil || slices.ContainsFunc(done, func(d os.FileInfo) bool { return os.SameFile(d, st) }) {
				continue
			}
			done = append(done, st)
			if !a.rec.holds(p, s) {
				continue
			}
			if err := a.rec.untag(p); err != nil {
				a.Log.Printf("finder tag %s: %v", p, err)
			}
		}
	}
	a.Log.Printf("marked safe: %s (%s %s)", e.Path, e.Kind, key)
	a.mu.Lock()
	for _, r := range a.recent {
		if r.Kind == e.Kind && r.TrustKey == key {
			r.MarkedSafe = true
		}
	}
	if a.latest != nil && a.latest.Kind == e.Kind && a.latest.TrustKey == key {
		a.latest.MarkedSafe = true
	}
	a.mu.Unlock()
	a.emit(Event{Kind: ItemsChanged})
	return errors.Join(errs...)
}

// ClearRecent hides every current entry from the recent list. Reports and
// the index are kept.
func (a *App) ClearRecent() error {
	a.mu.Lock()
	a.clearedAt = time.Now().UTC().Truncate(time.Second)
	a.recent = nil
	st := state{RecentClearedAt: a.clearedAt}
	a.mu.Unlock()
	err := a.saveState(st)
	a.emit(Event{Kind: ItemsChanged})
	return err
}

// state is binchk's own small settings file, <data>/state.json.
type state struct {
	RecentClearedAt time.Time `json:"recent_cleared_at"`
}

func (a *App) statePath() string { return filepath.Join(a.dataDir, "state.json") }

func (a *App) loadState() state {
	var s state
	if b, err := os.ReadFile(a.statePath()); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func (a *App) saveState(s state) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := a.statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.statePath())
}
