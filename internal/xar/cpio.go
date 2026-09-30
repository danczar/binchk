package xar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Limits bounds an extraction.
type Limits struct {
	MaxBytes   int64 // total bytes written
	MaxEntries int
}

// ErrLimit is returned (wrapped) when extraction stops at a limit; what was
// extracted so far is still usable.
var ErrLimit = errors.New("extraction limit reached")

// ExtractCPIO unpacks an odc ("070707") or newc ("070701") cpio stream into
// dir. It returns the number of bytes written.
func ExtractCPIO(ctx context.Context, r io.Reader, dir string, lim Limits) (int64, error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return 0, err
	}
	var written int64
	entries := 0
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		h, err := readHeader(r)
		if err != nil {
			return written, err
		}
		if h.name == "TRAILER!!!" {
			return written, nil
		}
		entries++
		if lim.MaxEntries > 0 && entries > lim.MaxEntries {
			return written, fmt.Errorf("%w: more than %d entries", ErrLimit, lim.MaxEntries)
		}
		body := io.LimitReader(r, h.size)
		dst, ok := safeJoin(root, h.name)
		mode := h.mode & 0o170000
		switch {
		case !ok || h.name == "." || h.name == "":
		case mode == 0o040000:
			os.MkdirAll(dst, 0o755)
		case mode == 0o120000 && h.size < 4096:
			target, _ := io.ReadAll(body)
			// Only links that resolve inside the extraction root.
			t := string(target)
			relDir, _ := filepath.Rel(root, filepath.Dir(dst))
			resolved := filepath.Clean(filepath.Join(relDir, t))
			if !filepath.IsAbs(t) && resolved != ".." && !strings.HasPrefix(resolved, ".."+string(filepath.Separator)) {
				os.MkdirAll(filepath.Dir(dst), 0o755)
				os.Symlink(t, dst)
			}
		case mode == 0o100000:
			if lim.MaxBytes > 0 && written+h.size > lim.MaxBytes {
				return written, fmt.Errorf("%w: %d bytes", ErrLimit, lim.MaxBytes)
			}
			os.MkdirAll(filepath.Dir(dst), 0o755)
			perm := fs.FileMode(h.mode&0o777) | 0o600 // no setuid/setgid/sticky
			f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
			if err == nil {
				n, cerr := io.Copy(f, body)
				f.Close()
				written += n
				if cerr != nil {
					return written, cerr
				}
			}
		}
		// Skip whatever of the body was not consumed, plus padding.
		if _, err := io.Copy(io.Discard, body); err != nil {
			return written, err
		}
		if h.pad > 0 {
			if _, err := io.CopyN(io.Discard, r, int64((h.pad-int(h.size%int64(h.pad)))%h.pad)); err != nil {
				return written, err
			}
		}
	}
}

type header struct {
	name string
	mode uint32
	size int64
	pad  int // data alignment (newc: 4, odc: none)
}

func readHeader(r io.Reader) (*header, error) {
	magic := make([]byte, 6)
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, err
	}
	switch string(magic) {
	case "070707": // odc: octal fields
		b := make([]byte, 70)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		oct := func(s string) (int64, error) { return strconv.ParseInt(s, 8, 64) }
		mode, e1 := oct(string(b[12:18]))
		namesize, e2 := oct(string(b[53:59]))
		size, e3 := oct(string(b[59:70]))
		if e1 != nil || e2 != nil || e3 != nil || namesize > 4096 || size < 0 {
			return nil, errors.New("cpio: bad odc header")
		}
		name := make([]byte, namesize)
		if _, err := io.ReadFull(r, name); err != nil {
			return nil, err
		}
		return &header{name: strings.TrimRight(string(name), "\x00"), mode: uint32(mode), size: size}, nil
	case "070701", "070702": // newc: hex fields, 4-byte alignment
		b := make([]byte, 104)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		hx := func(i int) (int64, error) { return strconv.ParseInt(string(b[i*8:i*8+8]), 16, 64) }
		mode, e1 := hx(1)
		size, e2 := hx(6)
		namesize, e3 := hx(11)
		if e1 != nil || e2 != nil || e3 != nil || namesize > 4096 || size < 0 {
			return nil, errors.New("cpio: bad newc header")
		}
		name := make([]byte, namesize)
		if _, err := io.ReadFull(r, name); err != nil {
			return nil, err
		}
		if p := (4 - (110+int(namesize))%4) % 4; p > 0 {
			io.CopyN(io.Discard, r, int64(p))
		}
		return &header{name: strings.TrimRight(string(name), "\x00"), mode: uint32(mode), size: size, pad: 4}, nil
	}
	return nil, fmt.Errorf("cpio: unknown magic %q", magic)
}

// safeJoin resolves name under root, refusing anything that escapes it.
func safeJoin(root, name string) (string, bool) {
	clean := filepath.Clean("/" + filepath.FromSlash(name))
	p := filepath.Join(root, clean)
	if p != root && !strings.HasPrefix(p, root+string(filepath.Separator)) {
		return "", false
	}
	return p, true
}
