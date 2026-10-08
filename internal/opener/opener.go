// Package opener opens files and folders with the desktop's default handler.
package opener

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func Open(path string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}
	return start(cmd)
}

// Reveal shows path selected in the file manager (Finder, Explorer); on
// Linux it opens the containing folder. If path is gone, its folder opens.
func Reveal(path string) error {
	if _, err := os.Lstat(path); err != nil {
		return Open(filepath.Dir(path))
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return start(revealCmd(path))
	}
	return Open(filepath.Dir(path))
}

func start(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}
