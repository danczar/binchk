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
	"github.com/danczar/binchk/internal/opener"
	"github.com/danczar/binchk/internal/quarantine"
)

const maxMenuItems = 15

type itemUI struct {
	root *systray.MenuItem
	done chan struct{}
}

type ui struct {
	a *app.App

	mu        sync.Mutex
	status    *systray.MenuItem
	latest    *systray.MenuItem
	quarMenu  *systray.MenuItem
	empty     *systray.MenuItem
	items     []*itemUI
	shownIDs  []string
	scanning  string
	lastError string
}

// Run blocks, running the tray event loop on the main thread.
func Run(a *app.App) {
	u := &ui{a: a}
	systray.Run(u.onReady, a.Stop)
}

func (u *ui) onReady() {
	u.setIcon(nil)
	systray.SetTooltip("binchk")

	u.status = systray.AddMenuItem("Starting…", "")
	u.status.Disable()
	u.latest = systray.AddMenuItem("No files analysed yet", "Open the most recent report")
	u.latest.Disable()
	systray.AddSeparator()
	u.quarMenu = systray.AddMenuItem("Quarantine", "Files held for review")
	u.empty = u.quarMenu.AddSubMenuItem("Empty", "")
	u.empty.Disable()
	systray.AddSeparator()
	mPause := systray.AddMenuItemCheckbox("Pause watching", "Stop analysing new files", false)
	mLogin := systray.AddMenuItemCheckbox("Start at login", "", autostart.Enabled())
	mReports := systray.AddMenuItem("Open reports folder", "")
	mQuarDir := systray.AddMenuItem("Open quarantine folder", "")
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
			case <-mQuarDir.ClickedCh:
				opener.Open(u.a.QuarantineDir())
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

// refresh redraws everything from app state. Cheap enough to call on
// every event; the quarantine submenu is only rebuilt when it changed.
func (u *ui) refresh() {
	u.mu.Lock()
	defer u.mu.Unlock()
	items := u.a.Items()
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
		u.latest.SetTitle(fmt.Sprintf("%s Latest: %s — %s · Open report", verdictMark(latest.Verdict), shorten(latest.Name, 32), latest.Verdict))
		u.latest.Enable()
		tip = fmt.Sprintf("binchk — %s: %s (risk %d/100)\n%s", latest.Verdict, latest.Name, latest.Score, shorten(latest.Summary, 120))
		if runtime.GOOS != "darwin" {
			tip += "\nClick to open the report."
		}
	}
	if scanning > 0 && u.scanning != "" {
		tip = "binchk — analysing " + shorten(u.scanning, 60) + "…"
	}
	systray.SetTooltip(tip)
	u.setIcon(items)
	if runtime.GOOS == "darwin" {
		if len(items) > 0 {
			systray.SetTitle(fmt.Sprint(len(items)))
		} else {
			systray.SetTitle("")
		}
	}

	// Quarantine submenu
	u.quarMenu.SetTitle(fmt.Sprintf("Quarantine (%d)", len(items)))
	ids := make([]string, 0, len(items))
	for i, e := range items {
		if i == maxMenuItems {
			break
		}
		ids = append(ids, e.ID+e.Verdict)
	}
	if slices.Equal(ids, u.shownIDs) {
		return
	}
	u.shownIDs = ids
	for _, it := range u.items {
		close(it.done)
		it.root.Remove()
	}
	u.items = nil
	if len(items) == 0 {
		u.empty.Show()
		return
	}
	u.empty.Hide()
	for i, e := range items {
		if i == maxMenuItems {
			break
		}
		u.items = append(u.items, u.addItem(e))
	}
}

func (u *ui) addItem(e *quarantine.Entry) *itemUI {
	label := fmt.Sprintf("%s %s — %s", verdictMark(e.Verdict), shorten(e.Name, 40), e.Verdict)
	if e.Verdict == "" {
		label = "⏳ " + shorten(e.Name, 40) + " — analysing"
	}
	root := u.quarMenu.AddSubMenuItem(label, strings.TrimSpace(e.Summary))
	info := root.AddSubMenuItem(fmt.Sprintf("Risk %d/100 · from %s", e.Score, shorten(e.OriginalPath, 50)), "")
	info.Disable()
	open := root.AddSubMenuItem("Open report", "")
	restore := root.AddSubMenuItem("Restore to original location", "Moves the file back and trusts its hash")
	del := root.AddSubMenuItem("Delete permanently", "")
	it := &itemUI{root: root, done: make(chan struct{})}
	id := e.ID
	go func() {
		for {
			select {
			case <-it.done:
				return
			case <-open.ClickedCh:
				if e.ReportPath != "" {
					opener.Open(e.ReportPath)
				}
			case <-restore.ClickedCh:
				if _, err := u.a.Restore(id); err != nil {
					u.a.Log.Printf("restore: %v", err)
				}
			case <-del.ClickedCh:
				if err := u.a.Delete(id); err != nil {
					u.a.Log.Printf("delete: %v", err)
				}
			}
		}
	}()
	return it
}

// setIcon reflects the worst verdict still in quarantine.
func (u *ui) setIcon(items []*quarantine.Entry) {
	if u.a.Scanning() > 0 {
		systray.SetIcon(icons.scanning)
		return
	}
	worst := ""
	for _, e := range items {
		switch {
		case e.Verdict == string(analyze.VerdictMalicious):
			worst = e.Verdict
		case e.Verdict == string(analyze.VerdictSuspicious) && worst == "":
			worst = e.Verdict
		}
	}
	switch worst {
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
