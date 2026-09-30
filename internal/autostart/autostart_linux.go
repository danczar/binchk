package autostart

import (
	"os"
	"path/filepath"
	"strings"
)

func desktopPath() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "autostart", "binchk.desktop")
}

func enabled() bool {
	_, err := os.Stat(desktopPath())
	return err == nil
}

func set(on bool) error {
	if !on {
		err := os.Remove(desktopPath())
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	quoted := `"` + strings.NewReplacer(`\`, `\\\\`, `"`, `\"`, "`", "\\`", "$", `\$`).Replace(exe()) + `"`
	entry := "[Desktop Entry]\nType=Application\nName=binchk\nComment=Checks new executables\nExec=" + quoted +
		"\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
	if err := os.MkdirAll(filepath.Dir(desktopPath()), 0o755); err != nil {
		return err
	}
	return os.WriteFile(desktopPath(), []byte(entry), 0o644)
}
