// Package tray is binchk's system-tray / menu-bar interface.
package tray

import (
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"

	"fyne.io/systray"

	"github.com/danczar/binchk/internal/analyze"
	"github.com/danczar/binchk/internal/app"
	"github.com/danczar/binchk/internal/autostart"
	"github.com/danczar/binchk/internal/index"
	"github.com/danczar/binchk/internal/opener"
)

const maxMenuItems = 15

type itemUI struct {
	root *systray.MenuItem
	done chan struct{}
}

type ui struct {
	a *app.App

	mu         sync.Mutex
	status     *systray.MenuItem
	latest     *systray.MenuItem
	recentMenu *systray.MenuItem
	empty      *systray.MenuItem
	clear      *systray.MenuItem
	items      []*itemUI
	shownKeys  []string
	scanning   string
	lastError  string
}

// Run blocks, running the tray event loop on the main thread.
func Run(a *app.App) {
	u := &ui{a: a}
	systray.Run(u.onReady, a.Stop)
}

func revealLabel() string {
	switch runtime.GOOS {
	case "darwin":
		return "Reveal in Finder"
	case "windows":
		return "Show in Explorer"
	}
	return "Open containing folder"
}

func (u *ui) onReady() {
	u.setIcon(nil)
	systray.SetTooltip("binchk")

	u.status = systray.AddMenuItem("Starting…", "")
	u.status.Disable()
	u.latest = systray.AddMenuItem("No files analysed yet", "Open the most recent report")
	u.latest.Disable()
	systray.AddSeparator()
	u.recentMenu = systray.AddMenuItem("Recent reports", "Files binchk analysed recently")
	u.empty = u.recentMenu.AddSubMenuItem("None", "")
	u.empty.Disable()
	systray.AddSeparator()
	mPause := systray.AddMenuItemCheckbox("Pause watching", "Stop analysing new files", false)
	mLogin := systray.AddMenuItemCheckbox("Start at login", "", autostart.Enabled())
	mReports := systray.AddMenuItem("Open reports folder", "")
	mSettings := systray.AddMenuItem("Edit settings…", "Opens config.json; restart binchk to apply")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit binchk", "")

	// Clicking the icon itself opens the latest report where the platform
	// separates primary click from the menu (Windows, most Linux trays).
	if runtime.GOOS != "darwin" {
		systray.SetOnTapped(u.openLatest)
	}

	u.a.Subscribe(u.onEvent)
	if err := u.a.Start(); err != nil {
		u.lastError = err.Error()
	}
	u.refresh()

	go func() {
		for {
			select {
			case <-u.latest.ClickedCh:
				u.openLatest()
			case <-mPause.ClickedCh:
				if mPause.Checked() {
					mPause.Uncheck()
					u.a.SetPaused(false)
				} else {
					mPause.Check()
					u.a.SetPaused(true)
				}
			case <-mLogin.ClickedCh:
				enable := !mLogin.Checked()
				if err := autostart.Set(enable); err != nil {
					u.a.Log.Printf("autostart: %v", err)
				} else if enable {
					mLogin.Check()
				} else {
					mLogin.Uncheck()
				}
			case <-mReports.ClickedCh:
				opener.Open(u.a.ReportsDir())
			case <-mSettings.ClickedCh:
				opener.Open(u.a.Config().Path())
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

func (u *ui) openLatest() {
	if e := u.a.Latest(); e != nil && e.ReportPath != "" {
		opener.Open(e.ReportPath)
	}
}

func (u *ui) onEvent(ev app.Event) {
	u.mu.Lock()
	switch ev.Kind {
	case app.ScanStarted:
		u.scanning = ev.Path
	case app.ScanFinished:
		u.scanning, u.lastError = "", ""
	case app.ScanFailed:
		u.scanning = ""
		if ev.Err != nil {
			u.lastError = ev.Err.Error()
		}
	}
	u.mu.Unlock()
	u.refresh()
}

func verdictMark(v string) string {
	switch v {
	case string(analyze.VerdictMalicious):
		return "🔴"
	case string(analyze.VerdictSuspicious):
		return "🟠"
	case string(analyze.VerdictClean):
		return "🟢"
	}
	return "⚪"
}

func shorten(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// flagged is a recent entry that still deserves attention.
func flagged(e *index.Entry) bool {
	return !e.MarkedSafe && (e.Verdict == string(analyze.VerdictMalicious) || e.Verdict == string(analyze.VerdictSuspicious))
}

// refresh redraws everything from app state. Cheap enough to call on
// every event; the recent-reports submenu is only rebuilt when it changed.
func (u *ui) refresh() {
	u.mu.Lock()
	defer u.mu.Unlock()
	recent := u.a.Recent()
	latest := u.a.Latest()
	scanning := u.a.Scanning()

	// Status line + tooltip
	nDirs := len(u.a.Config().WatchDirs)
	status := fmt.Sprintf("Watching %d folder%s", nDirs, map[bool]string{true: "", false: "s"}[nDirs == 1])
	switch {
	case u.a.Paused():
		status = "Paused"
	case scanning > 0:
		status = fmt.Sprintf("Analysing %d file(s)…", scanning)
	case u.lastError != "":
		status = "⚠ " + shorten(u.lastError, 60)
	}
	u.status.SetTitle(status)

	tip := "binchk — " + status
	if latest != nil {
		u.latest.SetTitle(fmt.Sprintf("%s Latest: %s — %s · Open report", verdictMark(latest.Verdict), shorten(latest.FileName, 32), latest.Verdict))
		u.latest.Enable()
		tip = fmt.Sprintf("binchk — %s: %s (risk %d/100)\n%s", latest.Verdict, latest.FileName, latest.Score, shorten(latest.Summary, 120))
		if runtime.GOOS != "darwin" {
			tip += "\nClick to open the report."
		}
	}
	if scanning > 0 && u.scanning != "" {
		tip = "binchk — analysing " + shorten(u.scanning, 60) + "…"
	}
	systray.SetTooltip(tip)
	u.setIcon(recent)
	nFlagged := 0
	for _, e := range recent {
		if flagged(e) {
			nFlagged++
		}
	}
	if runtime.GOOS == "darwin" {
		if nFlagged > 0 {
			systray.SetTitle(fmt.Sprint(nFlagged))
		} else {
			systray.SetTitle("")
		}
	}

	// Recent reports submenu
	if nFlagged > 0 {
		u.recentMenu.SetTitle(fmt.Sprintf("Recent reports (%d flagged)", nFlagged))
	} else {
		u.recentMenu.SetTitle("Recent reports")
	}
	if len(recent) > maxMenuItems {
		recent = recent[:maxMenuItems]
	}
	keys := make([]string, 0, len(recent))
	for _, e := range recent {
		keys = append(keys, fmt.Sprintf("%s|%s|%s|%s|%v", e.SHA256, e.Path, e.Verdict, e.AnalyzedAt, e.MarkedSafe))
	}
	if slices.Equal(keys, u.shownKeys) && u.shownKeys != nil {
		return
	}
	u.shownKeys = keys
	for _, it := range u.items {
		close(it.done)
		it.root.Remove()
	}
	u.items = nil
	if u.clear != nil {
		u.clear.Remove()
		u.clear = nil
	}
	if len(recent) == 0 {
		u.empty.Show()
		return
	}
	u.empty.Hide()
	for _, e := range recent {
		u.items = append(u.items, u.addItem(e))
	}
	u.clear = u.recentMenu.AddSubMenuItem("Clear recent reports", "Hides these entries from the menu; reports are kept")
	clear := u.clear
	done := u.items[0].done
	go func() {
		select {
		case <-done:
		case <-clear.ClickedCh:
			if err := u.a.ClearRecent(); err != nil {
				u.a.Log.Printf("clear recent: %v", err)
			}
		}
	}()
}

func (u *ui) addItem(e *index.Entry) *itemUI {
	label := fmt.Sprintf("%s %s — %s", verdictMark(e.Verdict), shorten(e.FileName, 40), e.Verdict)
	if e.MarkedSafe {
		label += " · marked safe"
	}
	root := u.recentMenu.AddSubMenuItem(label, strings.TrimSpace(e.Summary))
	info := root.AddSubMenuItem(fmt.Sprintf("Risk %d/100 · %s", e.Score, shorten(e.Path, 50)), "")
	info.Disable()
	open := root.AddSubMenuItem("Open report", "")
	reveal := root.AddSubMenuItem(revealLabel(), "")
	safe := root.AddSubMenuItem("Mark as safe", "Trust this file's content: allowlists its hash and removes binchk's tag")
	if e.MarkedSafe || !index.IsDigest(e.SHA256) {
		safe.Disable()
	}
	it := &itemUI{root: root, done: make(chan struct{})}
	go func() {
		for {
			select {
			case <-it.done:
				return
			case <-open.ClickedCh:
				if e.ReportPath != "" {
					opener.Open(e.ReportPath)
				}
			case <-reveal.ClickedCh:
				if e.Path != "" {
					opener.Reveal(e.Path)
				}
			case <-safe.ClickedCh:
				if err := u.a.MarkSafe(e.SHA256); err != nil {
					u.a.Log.Printf("mark safe: %v", err)
				}
			}
		}
	}()
	return it
}

// setIcon reflects the worst verdict among recent entries not marked safe.
func (u *ui) setIcon(recent []*index.Entry) {
	if u.a.Scanning() > 0 {
		systray.SetIcon(icons.scanning)
		return
	}
	switch worstVerdict(recent) {
	case string(analyze.VerdictMalicious):
		systray.SetIcon(icons.malicious)
	case string(analyze.VerdictSuspicious):
		systray.SetIcon(icons.suspicious)
	default:
		if runtime.GOOS == "darwin" {
			systray.SetTemplateIcon(icons.template, icons.template)
		} else {
			systray.SetIcon(icons.idle)
		}
	}
}

// worstVerdict is Malicious, Suspicious or "" over the flagged entries.
func worstVerdict(recent []*index.Entry) string {
	worst := ""
	for _, e := range recent {
		switch {
		case !flagged(e):
		case e.Verdict == string(analyze.VerdictMalicious):
			return e.Verdict
		default:
			worst = e.Verdict
		}
	}
	return worst
}
