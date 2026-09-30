// Package notify shows native desktop notifications. Where the platform
// allows it, clicking the notification opens the report.
package notify

import "strings"

type Urgency int

const (
	Normal Urgency = iota
	Critical
)

// Show displays a notification asynchronously; openPath (may be empty) is
// opened when the user clicks it on platforms that support actions.
func Show(title, body, openPath string, u Urgency) {
	go show(title, body, openPath, u)
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}
