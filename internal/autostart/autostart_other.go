//go:build !darwin && !linux && !windows

package autostart

import "errors"

func enabled() bool     { return false }
func set(on bool) error { return errors.New("autostart not supported on this platform") }
