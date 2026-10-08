// Package findertag sets binchk's verdict as a user-visible Finder tag
// ("binchk: Suspicious", orange) on macOS, keeping the user's own tags. On
// other systems every operation is a no-op.
package findertag

import (
	"strconv"
	"strings"
)

// Prefix starts every tag binchk writes; any tag with it belongs to binchk.
const Prefix = "binchk: "

// Finder label colour indices: 0 none, 1 gray, 2 green, 3 purple, 4 blue,
// 5 yellow, 6 red, 7 orange.
var colors = map[string]int{
	"Clean":      2,
	"Suspicious": 7,
	"Malicious":  6,
	"Error":      1,
}

// Tag returns the tag string stored for verdict: "binchk: Malicious\n6".
func Tag(verdict string) string {
	return Prefix + verdict + "\n" + strconv.Itoa(colors[verdict])
}

// tagName is a stored tag without its "\n<colour>" suffix.
func tagName(t string) string {
	name, _, _ := strings.Cut(t, "\n")
	return name
}

// merge replaces any binchk tag in existing with the one for verdict ("" to
// only remove), keeping every other tag in order. changed is false when the
// result equals existing.
func merge(existing []string, verdict string) (out []string, changed bool) {
	want := ""
	if verdict != "" {
		want = Tag(verdict)
	}
	found := false
	for _, t := range existing {
		if !strings.HasPrefix(tagName(t), Prefix) {
			out = append(out, t)
			continue
		}
		if t == want && !found {
			found = true
			out = append(out, t)
			continue
		}
		changed = true
	}
	if want != "" && !found {
		out = append(out, want)
		changed = true
	}
	return out, changed
}

// Set gives path the binchk tag for verdict, replacing any earlier binchk
// tag and keeping the user's tags. An empty verdict removes binchk's tag.
// path must be a regular file or an .app bundle directory; symbolic links
// are never followed. Existing tags that cannot be decoded are left alone
// and reported as an error.
func Set(path, verdict string) error { return set(path, verdict) }

// Clear removes binchk's tag from path, if any.
func Clear(path string) error { return set(path, "") }

// Get returns path's Finder tags as stored ("Name\n<colour>" or "Name").
func Get(path string) ([]string, error) { return get(path) }

// Supported reports whether this system has Finder tags.
func Supported() bool { return supported }
