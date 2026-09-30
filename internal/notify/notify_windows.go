package notify

import (
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// PowerShell's registered AppUserModelID lets an unpackaged program raise a
// toast without installing a Start-menu shortcut.
const psAUMID = `{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe`

func show(title, body, openPath string, u Urgency) {
	launch := ""
	if openPath != "" {
		// activationType=protocol + file:// URL opens the report on click.
		fu := (&url.URL{Scheme: "file", Path: "/" + filepath.ToSlash(openPath)}).String()
		launch = ` activationType="protocol" launch="` + xmlEscape(fu) + `"`
	}
	scenario := ""
	if u == Critical {
		scenario = ` scenario="reminder"`
	}
	toast := `<toast` + launch + scenario + `><visual><binding template="ToastGeneric"><text>` + xmlEscape(title) +
		`</text><text>` + xmlEscape(body) + `</text></binding></visual>` +
		map[bool]string{true: `<actions><action content="Dismiss" arguments="dismiss" activationType="system"/></actions>`, false: ""}[u == Critical] +
		`</toast>`
	ps := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	script := strings.Join([]string{
		`[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null`,
		`[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null`,
		`$x = New-Object Windows.Data.Xml.Dom.XmlDocument`,
		`$x.LoadXml(` + ps(toast) + `)`,
		`$t = New-Object Windows.UI.Notifications.ToastNotification $x`,
		`[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(` + ps(psAUMID) + `).Show($t)`,
	}, "\r\n")
	// Feed the script on stdin: no quoting pitfalls, no encoded blobs.
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "-")
	cmd.Stdin = strings.NewReader(script + "\r\n")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	_ = cmd.Run()
}
