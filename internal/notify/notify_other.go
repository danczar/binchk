//go:build !darwin && !linux && !windows

package notify

func show(title, body, openPath string, u Urgency) {}
