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
	MaxBytes   int64 // total entry body bytes, written or skipped
	MaxEntries int
}

// ErrLimit is returned (wrapped) when extraction stops at a limit; what was
// extracted so far is still usable.
var ErrLimit = errors.New("extraction limit reached")

// ExtractCPIO unpacks an odc ("070707") or newc ("070701") cpio stream into
// dir. It returns the number of bytes written. Every body byte read, written
// or discarded, counts toward lim.MaxBytes, and ctx is honoured mid-entry.
func ExtractCPIO(ctx context.Context, r io.Reader, dir string, lim Limits) (int64, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	// All writes go through root, which refuses any path that resolves
	// outside dir however the archive's symlinks are arranged.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	// No link left behind may resolve outside dir, whatever the outcome.
	// Links are checked against the real tree as they are created, and
	// every link under dir is checked again once it is final, because a
	// later entry can change how an earlier link resolves.
	links := &linkGuard{root: root, budget: linkBudget}
	defer links.prune()
	r = ctxReader{ctx, r}
	var written, consumed int64
	entries := 0
	dirs := map[string]bool{} // directories verified to be real (not links)
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
		if lim.MaxBytes > 0 && consumed+h.size > lim.MaxBytes {
			return written, fmt.Errorf("%w: %d bytes", ErrLimit, lim.MaxBytes)
		}
		consumed += h.size
		body := io.LimitReader(r, h.size)
		rel, ok := cleanName(h.name)
		mode := h.mode & 0o170000
		switch {
		case !ok:
		case mode == 0o040000:
			mkdirs(root, rel, dirs)
		case mode == 0o120000 && h.size < 4096:
			target, _ := io.ReadAll(body)
			// Only links whose target, resolved through the tree as it
			// stands (existing links included), stays inside the root.
			t := string(target)
			if !isAbsLink(t) && mkdirs(root, filepath.Dir(rel), dirs) &&
				links.inRoot(append(splitPath(filepath.Dir(rel)), splitPath(t)...)) {
				root.Symlink(t, rel)
			}
		case mode == 0o100000:
			if !mkdirs(root, filepath.Dir(rel), dirs) {
				break
			}
			perm := fs.FileMode(h.mode&0o777) | 0o600 // no setuid/setgid/sticky
			f, err := root.OpenFile(rel, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
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

// ctxReader fails reads once ctx is done, so a single huge entry cannot
// outlive the deadline.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// linkBudget bounds the path components resolved across all of one
// extraction's symlink checks. Real packages use a small fraction of it;
// once it is spent every remaining link is refused or removed (fails closed).
const linkBudget = 1 << 20

// maxLinkHops matches the kernel's MAXSYMLINKS on macOS.
const maxLinkHops = 32

// linkGuard decides whether symlinks stay inside the extraction root by
// resolving them against the real tree, component by component, following
// the links already present the way the kernel would.
type linkGuard struct {
	root   *os.Root
	budget int
}

// prune removes every link in the final tree under the root that resolves
// outside it: not only the links this extraction made, because the
// directory may already hold links (an earlier extraction into it) whose
// resolution the new entries change. inRoot rejects a path whose
// resolution leaves the root at any step, so removing a link can only make
// others dangle (the kernel fails on a missing component), never escape:
// one pass suffices.
func (g *linkGuard) prune() {
	var links []string
	fs.WalkDir(g.root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		// WalkDir does not descend into linked directories.
		if err == nil && d.Type()&fs.ModeSymlink != 0 {
			links = append(links, filepath.FromSlash(p))
		}
		return nil
	})
	for _, l := range links {
		if !g.inRoot(splitPath(l)) {
			g.root.Remove(l)
		}
	}
}

// inRoot resolves the root-relative path comps and reports whether every
// step stays within the root. Components that do not exist are taken
// lexically. Loops, too many hops and an exhausted budget report false.
func (g *linkGuard) inRoot(comps []string) bool {
	var cur []string // resolved components, none of them a link
	hops := 0
	for len(comps) > 0 {
		if g.budget--; g.budget < 0 {
			return false
		}
		c := comps[0]
		comps = comps[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if len(cur) == 0 {
				return false
			}
			cur = cur[:len(cur)-1]
			continue
		}
		p := filepath.Join(append(cur, c)...)
		fi, err := g.root.Lstat(p)
		if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
			// A file, a directory, or missing: nothing to follow.
			cur = append(cur, c)
			continue
		}
		if hops++; hops > maxLinkHops {
			return false
		}
		t, err := g.root.Readlink(p)
		if err != nil || isAbsLink(t) {
			return false
		}
		// The link's target replaces it, relative to its directory (cur).
		comps = append(splitPath(t), comps...)
	}
	return true
}

// isAbsLink reports a link target not anchored at the link's own
// directory: empty, absolute, rooted, or carrying a volume name.
func isAbsLink(t string) bool {
	return t == "" || t[0] == '/' || os.IsPathSeparator(t[0]) || filepath.IsAbs(t) || filepath.VolumeName(t) != ""
}

// splitPath splits on "/" and the OS separator without cleaning, so a ".."
// after a link climbs from the link's target, not lexically.
func splitPath(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool {
		return r == '/' || r < 0x80 && os.IsPathSeparator(uint8(r))
	})
}

// mkdirs creates dir (relative to root) and its parents, reporting false if
// any component is an existing symlink or non-directory: later entries are
// never written through a link, even one that stays inside root.
func mkdirs(root *os.Root, dir string, seen map[string]bool) bool {
	if dir == "." || seen[dir] {
		return true
	}
	if !mkdirs(root, filepath.Dir(dir), seen) {
		return false
	}
	if fi, err := root.Lstat(dir); err != nil {
		if root.Mkdir(dir, 0o755) != nil {
			return false
		}
	} else if !fi.IsDir() {
		return false
	}
	seen[dir] = true
	return true
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

// cleanName turns an archive name into a root-relative path, dropping any
// leading "/" or "..". It reports false for the root itself.
func cleanName(name string) (string, bool) {
	clean := filepath.Clean("/" + filepath.FromSlash(name))
	rel := strings.TrimLeft(clean, string(filepath.Separator))
	return rel, rel != "" && filepath.IsLocal(rel)
}
