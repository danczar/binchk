package notify

import (
	"net/url"
	"path/filepath"
)

// The Windows toast is raised by a hidden powershell.exe. Untrusted text (the
// download's file name, summaries) must never become PowerShell source:
// PowerShell treats U+2018..U+201B as single quotes too, and decodes stdin
// with the console code page, so no quoting scheme is safe. Instead the
// script is a constant and the toast XML travels in an environment variable
// (UTF-16 on Windows, so no code-page mangling either).
//
// It lives in a file built on every OS so it can be unit-tested anywhere.

// toastEnv names the environment variable carrying the toast XML.
const toastEnv = "BINCHK_TOAST_XML"

// toastScript is fed to `powershell.exe -Command -`. It must stay a constant.
// The AUMID is PowerShell's own registered one, which lets an unpackaged
// program raise a toast without installing a Start-menu shortcut.
const toastScript = "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null\r\n" +
	"[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null\r\n" +
	"$x = New-Object Windows.Data.Xml.Dom.XmlDocument\r\n" +
	"$x.LoadXml($env:" + toastEnv + ")\r\n" +
	"$t = New-Object Windows.UI.Notifications.ToastNotification $x\r\n" +
	"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe').Show($t)\r\n"

// toastXML builds the toast document. All dynamic text is XML-escaped.
func toastXML(title, body, openPath string, u Urgency) string {
	launch := ""
	if openPath != "" {
		// activationType=protocol + file:// URL opens the report on click.
		fu := (&url.URL{Scheme: "file", Path: "/" + filepath.ToSlash(openPath)}).String()
		launch = ` activationType="protocol" launch="` + xmlEscape(fu) + `"`
	}
	scenario, actions := "", ""
	if u == Critical {
		scenario = ` scenario="reminder"`
		actions = `<actions><action content="Dismiss" arguments="dismiss" activationType="system"/></actions>`
	}
	return `<toast` + launch + scenario + `><visual><binding template="ToastGeneric"><text>` + xmlEscape(title) +
		`</text><text>` + xmlEscape(body) + `</text></binding></visual>` + actions + `</toast>`
}
