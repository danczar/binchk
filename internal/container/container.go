// Package container inspects disk images and installer packages by opening
// them read-only and running the analysis engine over what they contain.
package container

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/danczar/binchk/internal/analyze"
	"github.com/danczar/binchk/internal/detect"
)

const (
	maxFiles    = 64        // executables analysed per container
	maxBytes    = 3 << 30   // total bytes analysed per container
	maxExpand   = 300 << 20 // pkgs up to this size get their payload expanded
	parallelism = 4         // concurrent engine runs (each already uses all cores)
)

// Supported reports whether files of format f can be opened here: disk
// images need macOS (they are mounted); installer packages are read by
// binchk itself on any OS.
func Supported(f detect.Format) bool {
	switch f {
	case detect.DiskImage:
		return supportsDMG
	case detect.InstallerPkg:
		return true
	case detect.AppBundle:
		return supportsDMG // Apple's verdicts are the point; macOS only
	}
	return false
}

// Options controls what Analyze may open.
type Options struct {
	// MountImages allows disk images to be mounted (macOS). When false,
	// images and UDIF polyglots are analysed as plain files only.
	MountImages bool
}

// Analyze dispatches on format: containers are opened and their contents
// inspected; everything else goes straight to the engine.
func Analyze(ctx context.Context, eng *analyze.Engine, path string, meta analyze.Meta) *analyze.Report {
	return AnalyzeWith(ctx, eng, path, meta, Options{MountImages: true})
}

// AnalyzeWith is Analyze with options.
func AnalyzeWith(ctx context.Context, eng *analyze.Engine, path string, meta analyze.Meta, opt Options) *analyze.Report {
	f := detect.SniffPath(path)
	mount := supportsDMG && opt.MountImages
	if f != detect.AppBundle && polyglot(path) {
		// Leading bytes and image both count: the file runs (or opens) as
		// the one and mounts as the other. Without mounting, the engine
		// analyses the leading side and flags the trailer.
		if !mount {
			return eng.Analyze(ctx, path, meta)
		}
		return analyzeContainer(ctx, eng, path, meta, f, true)
	}
	if !f.IsContainer() || !Supported(f) || (f == detect.DiskImage && !mount) {
		return eng.Analyze(ctx, path, meta)
	}
	return analyzeContainer(ctx, eng, path, meta, f, false)
}

// polyglot reports whether path carries a UDIF trailer behind some other
// leading content (an executable, a script, a package header, or any bytes
// before the image's data fork). Such a file still mounts, so both sides
// are inspected.
func polyglot(path string) bool {
	fh, err := os.Open(path)
	if err != nil {
		return false
	}
	defer fh.Close()
	st, err := fh.Stat()
	return err == nil && st.Mode().IsRegular() && detect.UDIFPolyglot(fh, st.Size())
}

// leadingFormat names a polyglot's leading side as the engine reports it.
func leadingFormat(path string) string {
	fh, err := os.Open(path)
	if err != nil {
		return "unknown"
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return "unknown"
	}
	if f := detect.SniffLeading(fh, st.Size()); f != detect.Unknown {
		return string(f)
	}
	if hasShebang(path) {
		return "script"
	}
	return "unknown"
}

func analyzeContainer(parent context.Context, eng *analyze.Engine, path string, meta analyze.Meta, f detect.Format, poly bool) *analyze.Report {
	start := time.Now()
	ctx, cancel := context.WithTimeout(parent, eng.Budget())
	defer cancel()
	r := &analyze.Report{
		ID: meta.ID, FileName: meta.FileName, OriginalPath: meta.OriginalPath, StoredPath: path,
		Provenance: meta.Provenance, DetectedAt: meta.DetectedAt, Format: string(f), Size: fileSize(path),
	}
	if r.FileName == "" {
		r.FileName = filepath.Base(path)
	}
	if r.OriginalPath == "" {
		r.OriginalPath = path
	}
	kind := f
	if poly {
		// Reported as its leading side, inspected as that and as an image.
		r.Format, kind = leadingFormat(path), detect.DiskImage
	}
	in := newInspector(ctx, eng, r, string(kind))
	in.poly = poly
	// A bundle is a directory: its identity is its main executable's hash
	// (what the allowlist and blocklist match on).
	hashTarget := path
	if f == detect.AppBundle {
		hashTarget = mainExecutable(ctx, path)
		in.goTask(func() {
			var total int64
			filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
				if err == nil && d.Type().IsRegular() {
					if info, err := d.Info(); err == nil {
						total += info.Size()
					}
				}
				return nil
			})
			in.mu.Lock()
			r.Size = total
			in.mu.Unlock()
		})
	}
	in.goTask(func() {
		t0 := time.Now()
		h, err := analyze.HashFile(ctx, hashTarget)
		in.timed("hash", t0, err)
		in.mu.Lock()
		r.Hashes = h
		in.mu.Unlock()
	})
	switch {
	case poly:
		// The leading side is the file itself: always analysed in full,
		// outside the limits on contained files.
		in.analyzeSelf(path, r.FileName, "leading content")
		if f == detect.InstallerPkg {
			in.inspectPkg(path, r.FileName, true)
		}
		in.inspectDMG(path, false)
	case f == detect.DiskImage:
		in.inspectDMG(path, true)
	case f == detect.InstallerPkg:
		in.inspectPkg(path, r.FileName, true)
	case f == detect.AppBundle:
		in.inspectApp(path, r.FileName, true, false)
	}
	in.wait()
	in.finalize(start)
	in.release()
	return r
}

// inspector accumulates results while a container's contents are analysed
// concurrently. Everything it produces is merged into one report.
type inspector struct {
	eng *analyze.Engine
	ctx context.Context
	r   *analyze.Report
	c   *analyze.Container

	mu       sync.Mutex
	findings []analyze.Finding // the container's own findings
	lifted   []analyze.Finding // findings of contained files
	timings  []analyze.Timing
	files    int
	bytes    int64
	sig      *analyze.Signature // signature of the primary app / package
	imageSig *analyze.Signature // the disk image's own (notarized) signature
	// poly marks a UDIF polyglot: no signature found on either side is
	// credited to it, since neither covers what the other side runs.
	poly bool
	// imageChecked closes once the disk image's own assessment is known.
	imageChecked chan struct{}

	wg       sync.WaitGroup
	sem      chan struct{}
	released []<-chan struct{} // engine runs that may still read files
	cleanup  []func()          // run after every engine run has released
	finish   []func()          // run after wg.Wait, before scoring
}

func newInspector(ctx context.Context, eng *analyze.Engine, r *analyze.Report, kind string) *inspector {
	c := &analyze.Container{Kind: kind}
	r.Container = c
	return &inspector{eng: eng, ctx: ctx, r: r, c: c, sem: make(chan struct{}, parallelism)}
}

func (in *inspector) add(fs ...analyze.Finding) {
	in.mu.Lock()
	in.findings = append(in.findings, fs...)
	in.mu.Unlock()
}

func (in *inspector) note(format string, a ...any) {
	in.mu.Lock()
	in.c.Notes = append(in.c.Notes, fmt.Sprintf(format, a...))
	in.mu.Unlock()
}

func (in *inspector) timed(name string, t0 time.Time, err error) {
	t := analyze.Timing{Name: name, Duration: time.Since(t0), Status: "ok"}
	if err != nil {
		t.Status, t.Error = "error", err.Error()
		if in.ctx.Err() != nil {
			t.Status, t.Error = "timeout", ""
		}
	}
	in.mu.Lock()
	in.timings = append(in.timings, t)
	in.mu.Unlock()
}

// goTask runs fn concurrently as part of the inspection.
func (in *inspector) goTask(fn func()) {
	in.wg.Add(1)
	go func() {
		defer in.wg.Done()
		fn()
	}()
}

// analyzeFile queues one contained file for full engine analysis. rel is
// the display path inside the container.
func (in *inspector) analyzeFile(abs, rel, kind string, size int64) {
	in.mu.Lock()
	if in.files >= maxFiles || in.bytes+size > maxBytes {
		in.c.Skipped++
		in.mu.Unlock()
		return
	}
	in.files++
	in.bytes += size
	in.mu.Unlock()
	in.runFile(abs, rel, kind)
}

// analyzeSelf analyses the container file itself as a plain file (a
// polyglot's leading side, an image that will not mount). It is not a
// contained file, so the per-container limits do not apply.
func (in *inspector) analyzeSelf(abs, rel, kind string) {
	in.runFile(abs, rel, kind)
}

func (in *inspector) runFile(abs, rel, kind string) {
	in.goTask(func() {
		select {
		case in.sem <- struct{}{}:
		case <-in.ctx.Done():
			in.mu.Lock()
			in.c.Skipped++
			in.mu.Unlock()
			return
		}
		cr, released := in.eng.AnalyzeWait(in.ctx, abs, analyze.Meta{FileName: filepath.Base(rel), OriginalPath: rel, SkipVerify: true})
		<-in.sem
		cf := analyze.ContainedFile{
			Path: rel, Kind: kind, Format: cr.Format, Arches: cr.Arches, Size: cr.Size, SHA256: cr.Hashes.SHA256,
			Verdict: cr.Verdict, Score: cr.Score, Summary: cr.Summary, Signer: cr.Signature.Signer,
			Findings: cr.Findings, Elapsed: cr.Elapsed, Truncated: cr.Truncated,
		}
		lifted := lift(rel, cr.Findings)
		if note, ok := in.eng.Blocklisted(cr.Hashes.SHA256); ok {
			in.add(analyze.Finding{ID: "hash-blocklist", Title: "Contains a blocklisted file",
				Severity: analyze.Critical, Category: "reputation", Evidence: []string{rel + ": " + note}})
		}
		in.mu.Lock()
		in.c.Files = append(in.c.Files, cf)
		in.released = append(in.released, released)
		in.lifted = append(in.lifted, lifted...)
		in.mu.Unlock()
	})
}

// lift re-labels a contained file's findings for the container report so
// that the same issue in many files merges into one finding (by ID) whose
// evidence names each file.
func lift(rel string, fs []analyze.Finding) []analyze.Finding {
	var out []analyze.Finding
	for _, f := range fs {
		if f.Severity == analyze.Info || f.ID == "truncated" || f.Category == "filename" {
			continue
		}
		g := f
		g.Evidence = nil
		if len(f.Evidence) == 0 {
			g.Evidence = []string{rel}
		}
		for i, ev := range f.Evidence {
			if i == 6 {
				g.Evidence = append(g.Evidence, fmt.Sprintf("%s: … %d more", rel, len(f.Evidence)-i))
				break
			}
			g.Evidence = append(g.Evidence, rel+": "+ev)
		}
		out = append(out, g)
	}
	return out
}

// imageNotarized waits (briefly) for the disk image assessment and reports
// whether the image itself is signed and notarized.
func (in *inspector) imageNotarized() bool {
	if in.poly || in.imageChecked == nil {
		return false
	}
	select {
	case <-in.imageChecked:
	case <-in.ctx.Done():
		return false
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.imageSig != nil
}

// onFinish registers fn to run after all tasks, before scoring.
func (in *inspector) onFinish(fn func()) {
	in.mu.Lock()
	in.finish = append(in.finish, fn)
	in.mu.Unlock()
}

// onRelease registers a cleanup to run once no engine goroutine can still
// be reading contained files (unmount, temp removal).
func (in *inspector) onRelease(fn func()) {
	in.mu.Lock()
	in.cleanup = append(in.cleanup, fn)
	in.mu.Unlock()
}

// wait blocks until all inspection tasks are done, then runs finishers.
func (in *inspector) wait() {
	in.wg.Wait()
	for _, f := range in.finish {
		f()
	}
}

// release runs cleanups (unmount, temp removal) once no engine goroutine can
// still be reading the files. Never blocks the caller.
func (in *inspector) release() {
	rel := append([]<-chan struct{}{}, in.released...)
	cleanup := in.cleanup
	go func() {
		for _, ch := range rel {
			<-ch
		}
		for i := len(cleanup) - 1; i >= 0; i-- {
			cleanup[i]()
		}
	}()
}

// finalize assembles the container report.
func (in *inspector) finalize(start time.Time) {
	r, c := in.r, in.c
	sort.SliceStable(c.Files, func(i, j int) bool {
		if c.Files[i].Score != c.Files[j].Score {
			return c.Files[i].Score > c.Files[j].Score
		}
		return c.Files[i].Path < c.Files[j].Path
	})
	for _, f := range c.Files {
		for _, a := range f.Arches {
			if !contains(r.Arches, a) {
				r.Arches = append(r.Arches, a)
			}
		}
	}
	if c.Skipped > 0 {
		in.findings = append(in.findings, analyze.Finding{ID: "container-skipped", Title: "Not every file was analysed",
			Detail:   fmt.Sprintf("%d file(s) exceeded the per-container limits (%d files / %d GiB) or the time budget.", c.Skipped, maxFiles, maxBytes>>30),
			Severity: analyze.Info, Category: "engine"})
	}
	// Prefer the app's verified signature; fall back to the notarized disk
	// image when the app could not be verified within the budget. A
	// polyglot earns no trust from either side.
	switch {
	case in.poly:
	case in.sig != nil && in.sig.Verified != nil:
		r.Signature = *in.sig
	case in.imageSig != nil:
		r.Signature = *in.imageSig
	case in.sig != nil:
		r.Signature = *in.sig
	}
	if in.ctx.Err() != nil {
		r.Truncated = true
		in.findings = append(in.findings, analyze.Finding{ID: "truncated", Title: "Analysis hit the time budget",
			Detail: "Some checks did not finish; the verdict is based on partial results.", Severity: analyze.Info, Category: "engine"})
	}
	worst := 0
	for _, f := range c.Files {
		worst = max(worst, f.Score)
	}
	r.Timings = in.timings
	in.eng.FinalizeContainer(r, in.findings, in.lifted, worst)
	r.AnalyzedAt = time.Now()
	r.Elapsed = time.Since(start)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// mainExecutable returns the path of a bundle's CFBundleExecutable.
func mainExecutable(ctx context.Context, app string) string {
	info, _ := readPlist(ctx, filepath.Join(app, "Contents", "Info.plist"))
	return filepath.Join(app, "Contents", "MacOS", info["CFBundleExecutable"])
}

func fileSize(p string) int64 {
	st, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return st.Size()
}

// isScriptName flags the double-clickable script types used by "run this
// installer" social-engineering disk images.
func isScriptName(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".command", ".sh", ".tool", ".zsh", ".bash", ".py", ".scpt", ".applescript", ".js":
		return true
	}
	return false
}
