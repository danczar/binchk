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

// xmlEscape escapes s for XML text or attributes and drops control characters
// XML 1.0 cannot carry, which would otherwise make the document fail to parse.
func xmlEscape(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' || (r >= 0x20 && r <= 0xD7FF) || (r >= 0xE000 && r <= 0xFFFD) || r >= 0x10000 {
			return r
		}
		return -1
	}, s) // invalid UTF-8 becomes U+FFFD
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}
