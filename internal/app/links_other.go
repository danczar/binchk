//go:build !unix

package app

import "os"

// linkCount is the number of hard links to the item st describes (0 when
// unknown).
func linkCount(os.FileInfo) uint64 { return 0 }
