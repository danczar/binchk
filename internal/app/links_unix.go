//go:build unix

package app

import (
	"os"
	"syscall"
)

// linkCount is the number of hard links to the item st describes (0 when
// unknown).
func linkCount(st os.FileInfo) uint64 {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return uint64(s.Nlink)
	}
	return 0
}
