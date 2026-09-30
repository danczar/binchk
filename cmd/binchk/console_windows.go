package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// attachConsole lets the GUI-subsystem build (no console window for the tray)
// still print output when run from a terminal as `binchk scan ...`.
func attachConsole() {
	const attachParentProcess = ^uint32(0) // (DWORD)-1
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")
	if r, _, _ := proc.Call(uintptr(attachParentProcess)); r == 0 {
		return
	}
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout, os.Stderr = f, f
	}
}
