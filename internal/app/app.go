// Package app ties the pipeline together: watcher -> quarantine -> analysis
// -> report -> notification. The tray and headless modes both drive it.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/danczar/binchk/internal/analyze"
	"github.com/danczar/binchk/internal/config"
	"github.com/danczar/binchk/internal/container"
	"github.com/danczar/binchk/internal/notify"
	"github.com/danczar/binchk/internal/provenance"
	"github.com/danczar/binchk/internal/quarantine"
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
	Entry *quarantine.Entry
	Err   error
}

type App struct {
	cfg        *config.Config
	eng        *analyze.Engine
	allow      *analyze.HashList
	store      *quarantine.Store
	reportsDir string
	dataDir    string
	Log        *log.Logger

	mu        sync.Mutex
	items     []*quarantine.Entry // quarantined, newest first
	latest    *quarantine.Entry   // most recently analysed file (any outcome)
	scanning  map[string]bool
	paused    bool
	suppress  map[string]time.Time // restored paths the watcher must ignore
	listeners []func(Event)
	sem       chan struct{}
	cancel    context.CancelFunc
}

// NewEngine builds an analysis engine from config (rules, hash lists).
func NewEngine(cfg *config.Config) (*analyze.Engine, error) {
	eng, _, err := newEngine(cfg)
	return eng, err
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

func New(cfg *config.Config, logToFile bool) (*App, error) {
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
	store, err := quarantine.Open(filepath.Join(data, "quarantine"))
	if err != nil {
		return nil, err
	}
	a := &App{
		cfg: cfg, eng: eng, allow: allow, store: store, dataDir: data, Log: lg,
		reportsDir: filepath.Join(data, "reports"),
		scanning:   map[string]bool{}, suppress: map[string]time.Time{},
		sem: make(chan struct{}, cfg.ConcurrentScans),
	}
	a.items, _ = store.List()
	if len(a.items) > 0 {
		a.latest = a.items[0]
	}
	return a, nil
}

func (a *App) Config() *config.Config { return a.cfg }
func (a *App) DataDir() string        { return a.dataDir }
func (a *App) QuarantineDir() string  { return a.store.Dir() }
func (a *App) ReportsDir() string     { return a.reportsDir }

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
func (a *App) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	w, err := watcher.New(a.cfg.WatchDirs, time.Duration(a.cfg.SettleDelay), a.cfg.IgnoreExtensions, a.isOwnPath, a.Log)
	if err != nil {
		return err
	}
	go w.Run(ctx)
	go func() {
		for f := range w.Found() {
			if a.Paused() {
				continue
			}
			// Disk images and installers only matter where they can run,
			// and are only opened when enabled.
			if f.Format.IsContainer() && (runtime.GOOS != "darwin" || !a.cfg.InspectInstallers || !container.Supported(f.Format)) {
				continue
			}
			go a.Handle(f.Path, f.At)
		}
	}()
	a.Log.Printf("binchk started; data in %s", a.dataDir)
	return nil
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

// Items returns quarantined entries, newest first.
func (a *App) Items() []*quarantine.Entry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]*quarantine.Entry{}, a.items...)
}

func (a *App) Latest() *quarantine.Entry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.latest
}

func (a *App) Scanning() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.scanning)
}

// Handle runs the full pipeline for one detected file.
func (a *App) Handle(path string, detectedAt time.Time) {
	a.mu.Lock()
	if until, ok := a.suppress[path]; ok && time.Now().Before(until) {
		a.mu.Unlock()
		return
	}
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

	if st, err := os.Stat(path); err == nil && a.cfg.MaxFileSize > 0 && st.Size() > a.cfg.MaxFileSize {
		a.Log.Printf("skip %s: %d bytes exceeds max_file_size", path, st.Size())
		return
	}
	a.emit(Event{Kind: ScanStarted, Path: path})

	// Provenance must be read before the move in case it crosses volumes
	// (xattrs / alternate data streams would not survive the copy).
	prov := provenance.Read(path)
	entry, err := a.store.Isolate(path)
	if err != nil {
		a.Log.Printf("quarantine %s: %v", path, err)
		a.emit(Event{Kind: ScanFailed, Path: path, Err: err})
		return
	}
	a.sem <- struct{}{}
	r := container.AnalyzeWith(context.Background(), a.eng, entry.StoredPath, analyze.Meta{
		ID: entry.ID, FileName: entry.Name, OriginalPath: path, Provenance: prov, DetectedAt: detectedAt,
	}, container.Options{MountImages: a.cfg.InspectInstallers})
	<-a.sem
	entry.SHA256, entry.Verdict, entry.Score, entry.Summary = r.Hashes.SHA256, string(r.Verdict), r.Score, r.Summary
	entry.ReportPath = filepath.Join(a.reportsDir, entry.ID+".html")
	r.Latency = time.Since(detectedAt)
	if err := report.Write(r, entry.ReportPath); err != nil {
		a.Log.Printf("report %s: %v", entry.ID, err)
	}
	_ = report.WriteJSON(r, filepath.Join(a.reportsDir, entry.ID+".json"))
	_ = a.store.Save(entry)
	a.Log.Printf("%s %s score=%d in %s (latency %s): %s", r.Verdict, path, r.Score,
		r.Elapsed.Round(time.Millisecond), r.Latency.Round(time.Millisecond), r.Summary)

	_, allowlisted := a.allow.Lookup(r.Hashes.SHA256)
	autoRestore := allowlisted || (a.cfg.AutoRestoreClean && r.Verdict == analyze.VerdictClean)
	a.mu.Lock()
	a.latest = entry
	if !autoRestore {
		a.items = append([]*quarantine.Entry{entry}, a.items...)
	}
	a.mu.Unlock()
	if autoRestore {
		if _, err := a.restore(entry); err != nil {
			a.Log.Printf("auto-restore %s: %v", path, err)
		}
	}
	a.emit(Event{Kind: ScanFinished, Path: path, Entry: entry})
	if a.cfg.Notifications && !allowlisted {
		a.notify(entry, autoRestore)
	}
}

func (a *App) notify(e *quarantine.Entry, restored bool) {
	title := fmt.Sprintf("%s: %s", e.Verdict, e.Name)
	body := e.Summary
	if restored {
		body += " (restored)"
	} else {
		body += " — quarantined; click to view the report."
	}
	u := notify.Normal
	if e.Verdict == string(analyze.VerdictMalicious) {
		u = notify.Critical
	}
	notify.Show(title, body, e.ReportPath, u)
}

// Restore returns an item to its original location and trusts its hash so
// the same file is not quarantined again.
func (a *App) Restore(id string) (string, error) {
	e := a.take(id)
	if e == nil {
		return "", errors.New("no such item")
	}
	dst, err := a.restore(e)
	if err != nil {
		a.put(e)
		return "", err
	}
	if e.SHA256 != "" {
		if err := a.allow.Add(e.SHA256, "restored by user: "+e.Name); err != nil {
			a.Log.Printf("allowlist: %v", err)
		}
	}
	a.Log.Printf("restored %s -> %s", e.Name, dst)
	a.emit(Event{Kind: ItemsChanged})
	return dst, nil
}

func (a *App) restore(e *quarantine.Entry) (string, error) {
	// Suppress the watcher event the move back will generate. The path may
	// get a " (restored N)" suffix, so suppress the original too.
	a.mu.Lock()
	until := time.Now().Add(10*time.Second + time.Duration(a.cfg.SettleDelay))
	a.suppress[e.OriginalPath] = until
	a.mu.Unlock()
	dst, err := a.store.Restore(e)
	if err == nil {
		a.mu.Lock()
		a.suppress[dst] = until
		for p, t := range a.suppress {
			if time.Now().After(t) {
				delete(a.suppress, p)
			}
		}
		a.mu.Unlock()
	}
	return dst, err
}

// Delete permanently removes a quarantined file. Its report is kept.
func (a *App) Delete(id string) error {
	e := a.take(id)
	if e == nil {
		return errors.New("no such item")
	}
	if err := a.store.Delete(e); err != nil {
		a.put(e)
		return err
	}
	a.Log.Printf("deleted %s", e.Name)
	a.emit(Event{Kind: ItemsChanged})
	return nil
}

func (a *App) take(id string) *quarantine.Entry {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i, e := range a.items {
		if e.ID == id {
			a.items = append(a.items[:i:i], a.items[i+1:]...)
			return e
		}
	}
	return nil
}

func (a *App) put(e *quarantine.Entry) {
	a.mu.Lock()
	a.items = append([]*quarantine.Entry{e}, a.items...)
	a.mu.Unlock()
	a.emit(Event{Kind: ItemsChanged})
}
