package notify

import (
	"net/url"
	"os/exec"
	"strings"
)

func show(title, body, openPath string, u Urgency) {
	// terminal-notifier supports click-to-open; osascript notifications
	// cannot carry an action, so the tray icon is the click target there.
	if tn, err := exec.LookPath("terminal-notifier"); err == nil {
		args := []string{"-title", "binchk", "-subtitle", title, "-message", body, "-group", "binchk-" + openPath}
		if openPath != "" {
			args = append(args, "-open", (&url.URL{Scheme: "file", Path: openPath}).String())
		}
		if u == Critical {
			args = append(args, "-sound", "Basso")
		}
		if exec.Command(tn, args...).Run() == nil {
			return
		}
	}
	esc := func(s string) string { return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) }
	script := `display notification "` + esc(body) + `" with title "binchk" subtitle "` + esc(title) + `"`
	if u == Critical {
		script += ` sound name "Basso"`
	}
	_ = exec.Command("/usr/bin/osascript", "-e", script).Run()
}
