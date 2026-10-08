//go:build unix

package bundleid

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO or symlink swapped in after the type check neither blocks nor is
// followed.
func TestOpenNoFollow(t *testing.T) {
	d := t.TempDir()
	fifo := filepath.Join(d, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() {
		f, err := openNoFollow(fifo)
		if err == nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("opening a FIFO blocked")
	}
	os.WriteFile(filepath.Join(d, "real"), []byte("x"), 0o644)
	os.Symlink("real", filepath.Join(d, "link"))
	if f, err := openNoFollow(filepath.Join(d, "link")); err == nil {
		f.Close()
		t.Fatal("symlink was followed")
	}
}
