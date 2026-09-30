// Package autostart registers binchk to launch at login.
package autostart

import (
	"os"
	"path/filepath"
)

func exe() string {
	p, err := os.Executable()
	if err != nil {
		return "binchk"
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// Enabled reports whether binchk is registered to start at login.
func Enabled() bool { return enabled() }

// Set enables or disables start at login.
func Set(on bool) error { return set(on) }
