//go:build darwin || linux

package provenance

import (
	"strings"

	"golang.org/x/sys/unix"

	"github.com/danczar/binchk/internal/analyze"
	"github.com/danczar/binchk/internal/bplist"
)

func getxattr(path, name string) []byte {
	buf := make([]byte, 4096)
	n, err := unix.Getxattr(path, name, buf)
	if err != nil || n <= 0 {
		return nil
	}
	return buf[:n]
}

func read(path string) analyze.Provenance {
	var p analyze.Provenance
	// macOS: "flags;hex-time;agent;uuid"
	if q := getxattr(path, "com.apple.quarantine"); q != nil {
		if parts := strings.Split(string(q), ";"); len(parts) >= 3 {
			p.Agent = parts[2]
		}
	}
	if w := getxattr(path, "com.apple.metadata:kMDItemWhereFroms"); w != nil {
		urls := bplist.Strings(w)
		if len(urls) > 0 {
			p.Source = urls[0]
		}
		if len(urls) > 1 {
			p.Referrer = urls[1]
		}
	}
	// Linux: Chromium and Firefox set freedesktop origin attributes.
	if u := getxattr(path, "user.xdg.origin.url"); u != nil {
		p.Source = string(u)
	}
	if r := getxattr(path, "user.xdg.referrer.url"); r != nil {
		p.Referrer = string(r)
	}
	return p
}
