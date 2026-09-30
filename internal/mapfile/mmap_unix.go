//go:build darwin || linux || freebsd || openbsd || netbsd

package mapfile

import (
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func mmap(f *os.File, size int) ([]byte, func() error, error) {
	data, err := unix.Mmap(int(f.Fd()), 0, size, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, nil, err
	}
	// Linux treats WILLNEED as asynchronous readahead. macOS pages the whole
	// range in synchronously, which on a compressed disk image blocks for
	// seconds where the deadline can't interrupt it — so only hint on Linux.
	if runtime.GOOS == "linux" {
		_ = unix.Madvise(data, unix.MADV_WILLNEED)
	}
	return data, func() error { return unix.Munmap(data) }, nil
}
