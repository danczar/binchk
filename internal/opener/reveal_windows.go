package opener

import (
	"os/exec"
	"syscall"
)

// revealCmd runs `explorer /select,"<path>"`. Explorer parses its own
// command line and does not accept the argument quoted as a whole, so the
// line is built by hand; Windows paths cannot contain '"'.
func revealCmd(path string) *exec.Cmd {
	cmd := exec.Command("explorer.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: `explorer.exe /select,"` + path + `"`}
	return cmd
}
