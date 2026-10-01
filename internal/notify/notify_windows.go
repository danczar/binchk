package notify

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func show(title, body, openPath string, u Urgency) {
	// The script is constant; the toast XML (with the untrusted file name)
	// goes in the environment and is never parsed as PowerShell. See toast.go.
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "-")
	cmd.Env = append(os.Environ(), toastEnv+"="+toastXML(title, body, openPath, u))
	cmd.Stdin = strings.NewReader(toastScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	_ = cmd.Run()
}
