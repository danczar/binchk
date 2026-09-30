// Package watcher reports newly arrived executables in a set of folders.
// Files are only reported once they have stopped changing, so downloads and
// copies in progress are never analysed half-written.
package watcher

import (
	"context"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/danczar/binchk/internal/config"
	"github.com/danczar/binchk/internal/detect"
)

type Found struct {
	Path   string
	Format detect.Format
	At     time.Time // when writes to the file stopped (latency origin)
}

type pending struct {
	last  time.Time // last filesystem event or observed change
	size  int64
	mtime time.Time
	first time.Time
	// bundle entries track a whole .app tree (unzip / Finder copy write many
	// files); count is its number of entries.
	bundle bool
	count  int
}

// treeState summarises a directory tree so a bundle can be considered
// complete once it stops changing.
func treeState(root string) (count int, size int64, mtime time.Time) {
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || count > 500000 {
			return nil
		}
		count++
		if info, err := d.Info(); err == nil {
			size += info.Size()
			if info.ModTime().After(mtime) {
				mtime = info.ModTime()
			}
		}
		return nil
	})
	return
}

// touchBundle starts (or extends) the settle period for an app bundle.
func (w *Watcher) touchBundle(p string) {
	if inBundle(p) { // only top-level bundles; nested apps are part of their parent
		return
	}
	now := time.Now()
	if pd, ok := w.pending[p]; ok {
		pd.last = now
		return
	}
	pd := &pending{last: now, first: now, bundle: true, size: -1}
	pd.count, pd.size, pd.mtime = treeState(p)
	w.pending[p] = pd
}

type Watcher struct {
	fsw       *fsnotify.Watcher
	settle    time.Duration
	ignoreExt map[string]bool
	skip      func(path string) bool
	recursive map[string]bool // watched root -> recursive
	pending   map[string]*pending
	seen      map[string]time.Time // path -> mtime already reported
	log       *log.Logger
	out       chan Found
}

// New starts watching dirs. skip, if non-nil, excludes paths (e.g. binchk's
// own data directory).
func New(dirs []config.WatchDir, settle time.Duration, ignoreExts []string, skip func(string) bool, lg *log.Logger) (*Watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	w := &Watcher{
		fsw: fsw, settle: settle, skip: skip, log: lg,
		ignoreExt: map[string]bool{}, recursive: map[string]bool{},
		pending: map[string]*pending{}, seen: map[string]time.Time{},
		out: make(chan Found, 64),
	}
	for _, e := range ignoreExts {
		w.ignoreExt[strings.ToLower(e)] = true
	}
	for _, d := range dirs {
		abs, err := filepath.Abs(d.Path)
		if err != nil {
			continue
		}
		if err := w.addTree(abs, d.Recursive); err != nil {
			lg.Printf("watch %s: %v", abs, err)
			continue
		}
		w.recursive[abs] = d.Recursive
		lg.Printf("watching %s (recursive=%v)", abs, d.Recursive)
	}
	return w, nil
}

func (w *Watcher) Found() <-chan Found { return w.out }

func (w *Watcher) addTree(root string, recursive bool) error {
	if err := w.fsw.Add(root); err != nil {
		return err
	}
	if !recursive {
		return nil
	}
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() || p == root {
			return nil
		}
		if (w.skip != nil && w.skip(p)) || inBundle(filepath.Join(p, "x")) {
			return filepath.SkipDir
		}
		if err := w.fsw.Add(p); err != nil {
			w.log.Printf("watch %s: %v", p, err)
		}
		return nil
	})
}

// underRecursive reports whether dir lies inside a recursively watched root.
func (w *Watcher) underRecursive(dir string) bool {
	for root, rec := range w.recursive {
		if rec && (dir == root || strings.HasPrefix(dir, root+string(filepath.Separator))) {
			return true
		}
	}
	return false
}

// Run processes events until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context) {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	defer w.fsw.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			w.handle(ev)
		case err, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			w.log.Printf("watcher: %v", err)
		case now := <-tick.C:
			w.poll(now)
		}
	}
}

// bundleExts are macOS bundle directories. Their contents are one signed
// unit: pulling the executable out would break the app, so binchk leaves
// extracted bundles alone and relies on Gatekeeper's bundle-level checks.
var bundleExts = []string{".app", ".framework", ".bundle", ".appex", ".xpc", ".kext", ".plugin", ".systemextension"}

func isAppDir(p string) bool { return strings.EqualFold(filepath.Ext(p), ".app") }

// bundleRoot returns the outermost bundle directory containing p, or "".
func bundleRoot(p string) string {
	root := ""
	for dir := filepath.Dir(p); ; dir = filepath.Dir(dir) {
		ext := strings.ToLower(filepath.Ext(dir))
		for _, b := range bundleExts {
			if ext == b {
				root = dir
			}
		}
		if parent := filepath.Dir(dir); parent == dir {
			return root
		}
	}
}

func inBundle(p string) bool {
	for dir := filepath.Dir(p); ; dir = filepath.Dir(dir) {
		ext := strings.ToLower(filepath.Ext(dir))
		for _, b := range bundleExts {
			if ext == b {
				return true
			}
		}
		if parent := filepath.Dir(dir); parent == dir {
			return false
		}
	}
}

func (w *Watcher) handle(ev fsnotify.Event) {
	p := ev.Name
	if w.skip != nil && w.skip(p) {
		return
	}
	if ev.Has(fsnotify.Remove) || ev.Has(fsnotify.Rename) {
		// Rename events carry the old name; the new name arrives as Create.
		delete(w.pending, p)
		return
	}
	if !ev.Has(fsnotify.Create) && !ev.Has(fsnotify.Write) && !ev.Has(fsnotify.Chmod) {
		return
	}
	st, err := os.Lstat(p)
	if err != nil {
		return
	}
	if st.IsDir() {
		if ev.Has(fsnotify.Create) && isAppDir(p) {
			w.touchBundle(p)
			return
		}
		if ev.Has(fsnotify.Create) && w.underRecursive(filepath.Dir(p)) && !inBundle(filepath.Join(p, "x")) {
			_ = w.addTree(p, true)
			// Files may have landed before the watch existed (e.g. a moved
			// folder); queue them all.
			filepath.WalkDir(p, func(fp string, d fs.DirEntry, err error) error {
				switch {
				case err != nil:
				case d.IsDir() && isAppDir(fp):
					w.touchBundle(fp)
					return filepath.SkipDir
				case d.Type().IsRegular():
					w.touch(fp)
				}
				return nil
			})
		}
		return
	}
	if !st.Mode().IsRegular() {
		return
	}
	w.touch(p)
}

func (w *Watcher) touch(p string) {
	if b := bundleRoot(p); b != "" {
		if pd, ok := w.pending[b]; ok {
			pd.last = time.Now() // still being written
		}
		return
	}
	if w.ignoreExt[strings.ToLower(filepath.Ext(p))] {
		return
	}
	now := time.Now()
	if pd, ok := w.pending[p]; ok {
		pd.last = now
		return
	}
	pd := &pending{last: now, first: now, size: -1}
	// Record the current state now so an already-complete file is confirmed
	// after a single settle period.
	if st, err := os.Lstat(p); err == nil {
		pd.size, pd.mtime = st.Size(), st.ModTime()
	}
	w.pending[p] = pd
}

func (w *Watcher) poll(now time.Time) {
	for p, pd := range w.pending {
		if pd.bundle {
			w.pollBundle(p, pd, now)
			continue
		}
		if now.Sub(pd.last) < w.settle {
			continue
		}
		st, err := os.Lstat(p)
		if err != nil || !st.Mode().IsRegular() {
			delete(w.pending, p)
			continue
		}
		if st.Size() != pd.size || !st.ModTime().Equal(pd.mtime) {
			// Still changing (or first look): wait another settle period.
			pd.size, pd.mtime, pd.last = st.Size(), st.ModTime(), now
			if now.Sub(pd.first) > 6*time.Hour {
				delete(w.pending, p)
			}
			continue
		}
		delete(w.pending, p)
		if st.Size() == 0 {
			continue
		}
		if m, ok := w.seen[p]; ok && m.Equal(st.ModTime()) {
			continue
		}
		f := detect.SniffFile(p)
		if f == detect.Unknown {
			continue
		}
		w.seen[p] = st.ModTime()
		if len(w.seen) > 4096 {
			clear(w.seen)
		}
		select {
		case w.out <- Found{Path: p, Format: f, At: pd.last}:
		default:
			w.log.Printf("queue full, dropping %s", p)
		}
	}
}

// pollBundle reports an app bundle once its whole tree has been unchanged
// for a settle period (at least a second: archive tools pause between files).
func (w *Watcher) pollBundle(p string, pd *pending, now time.Time) {
	settle := max(w.settle, time.Second)
	if now.Sub(pd.last) < settle {
		return
	}
	if !detect.IsAppBundle(p) {
		if _, err := os.Stat(p); err != nil || now.Sub(pd.first) > 10*time.Minute {
			delete(w.pending, p) // gone, or never became a real bundle
		}
		pd.last = now
		return
	}
	count, size, mtime := treeState(p)
	if count != pd.count || size != pd.size || !mtime.Equal(pd.mtime) {
		pd.count, pd.size, pd.mtime, pd.last = count, size, mtime, now
		return
	}
	delete(w.pending, p)
	if m, ok := w.seen[p]; ok && m.Equal(mtime) {
		return
	}
	w.seen[p] = mtime
	select {
	case w.out <- Found{Path: p, Format: detect.AppBundle, At: pd.last}:
	default:
		w.log.Printf("queue full, dropping %s", p)
	}
}

// ScanExisting queues every file already present in the watched folders.
// It must be called before Run.
func (w *Watcher) ScanExisting() {
	for root, rec := range w.recursive {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrPermission) {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() && p != root && isAppDir(p) {
				w.touchBundle(p)
				return filepath.SkipDir
			}
			if d.IsDir() && p != root && (!rec || (w.skip != nil && w.skip(p))) {
				return filepath.SkipDir
			}
			if d.Type().IsRegular() {
				w.touch(p)
			}
			return nil
		})
	}
}
