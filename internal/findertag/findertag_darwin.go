package findertag

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/danczar/binchk/internal/bplist"
)

const (
	supported = true
	attrName  = "com.apple.metadata:_kMDItemUserTags"
)

// open returns a descriptor for path that is guaranteed to be the regular
// file or .app directory itself, never a symlink's target. O_NONBLOCK keeps
// a FIFO swapped in at the last moment from blocking the open.
func open(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, err
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		return fd, nil
	case unix.S_IFDIR:
		if strings.EqualFold(filepath.Ext(path), ".app") {
			return fd, nil
		}
	}
	unix.Close(fd)
	return -1, fmt.Errorf("findertag: %s is not a regular file or app bundle", path)
}

// read returns the tags stored on fd and whether the attribute exists.
func read(fd int) ([]string, bool, error) {
	for range 3 {
		n, err := unix.Fgetxattr(fd, attrName, nil)
		if errors.Is(err, unix.ENOATTR) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		buf := make([]byte, n+64)
		n, err = unix.Fgetxattr(fd, attrName, buf)
		if errors.Is(err, unix.ERANGE) {
			continue // grew in between
		}
		if errors.Is(err, unix.ENOATTR) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		tags, err := bplist.DecodeStrings(buf[:n])
		if err != nil {
			return nil, true, fmt.Errorf("findertag: existing tags unreadable, left untouched: %w", err)
		}
		return tags, true, nil
	}
	return nil, false, unix.ERANGE
}

func get(path string) ([]string, error) {
	fd, err := open(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	tags, _, err := read(fd)
	return tags, err
}

func set(path, verdict string) error {
	fd, err := open(path)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	existing, present, err := read(fd)
	if err != nil {
		return err
	}
	tags, changed := merge(existing, verdict)
	switch {
	case !changed:
		return nil
	case len(tags) == 0 && present:
		err = unix.Fremovexattr(fd, attrName)
		if errors.Is(err, unix.ENOATTR) {
			err = nil
		}
	default:
		err = unix.Fsetxattr(fd, attrName, bplist.EncodeStrings(tags), 0)
	}
	if err != nil {
		return fmt.Errorf("findertag %s: %w", path, err)
	}
	return nil
}
