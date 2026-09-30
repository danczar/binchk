package notify

import (
	"os/exec"
	"strings"

	"github.com/danczar/binchk/internal/opener"
)

func show(title, body, openPath string, u Urgency) {
	urgency := "normal"
	icon := "dialog-information"
	if u == Critical {
		urgency, icon = "critical", "dialog-warning"
	}
	base := []string{"-a", "binchk", "-u", urgency, "-i", icon}
	if openPath != "" {
		// libnotify >= 0.7.9: --wait blocks until closed and prints the
		// chosen action key.
		args := append(append([]string{}, base...), "--action=open=Open report", "--wait", title, body)
		out, err := exec.Command("notify-send", args...).Output()
		if err == nil {
			if strings.TrimSpace(string(out)) == "open" {
				opener.Open(openPath)
			}
			return
		}
	}
	_ = exec.Command("notify-send", append(base, title, body)...).Run()
}
