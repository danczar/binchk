//go:build !unix

package bundleid

import "os"

// openNoFollow opens p for reading. App bundles are a macOS concept; other
// platforms have no FIFO race to guard against here.
func openNoFollow(p string) (*os.File, error) { return os.Open(p) }
