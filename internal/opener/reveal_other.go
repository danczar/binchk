//go:build !windows

package opener

import "os/exec"

// revealCmd is Finder's "reveal" (only used on macOS).
func revealCmd(path string) *exec.Cmd { return exec.Command("open", "-R", path) }
