// Package analyze performs fast static triage of executable binaries.
package analyze

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/danczar/binchk/internal/detect"
	"github.com/danczar/binchk/internal/mapfile"
)

// Options configures an Engine.
type Options struct {
	Budget           time.Duration // hard deadline for one analysis
	ExtraRules       []Rule        // user rules appended to the built-ins
	Blocklist        *HashList
	Allowlist        *HashList
	VerifySignatures bool
	Workers          int
}

type Engine struct {
	opt   Options
	rules *ruleSet
}

func NewEngine(opt Options) (*Engine, error) {
	if opt.Budget <= 0 {
		opt.Budget = 10 * time.Second
	}
	if opt.Workers <= 0 {
		opt.Workers = runtime.NumCPU()
	}
	rs, err := compileRules(append(append([]Rule{}, builtinRules...), opt.ExtraRules...))
	if err != nil {
		return nil, err
	}
	return &Engine{opt: opt, rules: rs}, nil
}

// session holds one in-flight analysis. Tasks compute privately and publish
// through commit(); once the deadline passes commit() refuses further writes,
// so a straggling task can never race with report finalisation.
type session struct {
	mu       sync.Mutex
	closed   bool
	r        *Report
	findings []Finding
	content  *contentResult
	format   *formatResult
	goFinds  []Finding
	// OS signature verification result, if it ran.
	verified     *bool
	verifyDetail string
}

func (s *session) commit(f func()) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	f()
	return true
}

type task struct {
	name string
	fn   func(ctx context.Context) error
}

// Budget is the per-analysis deadline.
func (e *Engine) Budget() time.Duration { return e.opt.Budget }

// Analyze inspects the file at path. It always returns a report; on timeout
// the report is marked Truncated and contains whatever finished in time.
func (e *Engine) Analyze(parent context.Context, path string, meta Meta) *Report {
	r, _ := e.AnalyzeWait(parent, path, meta)
	return r
}

// AnalyzeWait is Analyze plus a channel that closes once every analysis
// goroutine has exited and the file is unmapped. Callers that are about to
// unmount the volume holding path must wait for it: a straggling parser
// reading an unmounted mapping would crash the process.
func (e *Engine) AnalyzeWait(parent context.Context, path string, meta Meta) (*Report, <-chan struct{}) {
	released := make(chan struct{})
	start := time.Now()
	r := &Report{
		ID: meta.ID, FileName: meta.FileName, OriginalPath: meta.OriginalPath, StoredPath: path,
		Provenance: meta.Provenance, DetectedAt: meta.DetectedAt,
	}
	if r.FileName == "" {
		r.FileName = filepath.Base(path)
	}
	if r.OriginalPath == "" {
		r.OriginalPath = path
	}
	fail := func(err error) (*Report, <-chan struct{}) {
		r.Verdict = VerdictError
		r.Summary = err.Error()
		r.Findings = []Finding{}
		r.AnalyzedAt = time.Now()
		r.Elapsed = time.Since(start)
		close(released)
		return r, released
	}
	mf, err := mapfile.Open(path)
	if err != nil {
		return fail(err)
	}
	data := mf.Data
	r.Size = int64(len(data))
	format := detect.Sniff(byteReaderAt(data), r.Size)
	r.Format = string(format)
	if format == detect.Unknown {
		r.Format = "unknown"
		if len(data) > 2 && data[0] == '#' && data[1] == '!' {
			r.Format = "script"
		}
	}

	ctx, cancel := context.WithTimeout(parent, e.opt.Budget)
	defer cancel()
	s := &session{r: r}

	hashTask := func(name string, h hash.Hash, dst *string) task {
		return task{name, func(ctx context.Context) error {
			for off := 0; off < len(data); off += 4 << 20 {
				if err := ctx.Err(); err != nil {
					return err
				}
				h.Write(data[off:min(off+4<<20, len(data))])
			}
			sum := hex.EncodeToString(h.Sum(nil))
			s.commit(func() { *dst = sum })
			return nil
		}}
	}
	tasks := []task{
		hashTask("sha256", sha256.New(), &r.Hashes.SHA256),
		hashTask("sha1", sha1.New(), &r.Hashes.SHA1),
		hashTask("md5", md5.New(), &r.Hashes.MD5),
		{"content scan", func(ctx context.Context) error {
			cr, err := scanContent(ctx, data, e.rules, e.opt.Workers)
			if err != nil {
				return err
			}
			s.commit(func() { s.content = cr })
			return nil
		}},
		{"format: " + r.Format, func(ctx context.Context) error {
			var fr *formatResult
			var err error
			switch format {
			case detect.PE:
				fr, err = analyzePE(data)
			case detect.ELF:
				fr, err = analyzeELF(data)
			case detect.MachO, detect.MachOFat:
				fr, err = analyzeMachO(data, format == detect.MachOFat)
			default:
				return nil
			}
			if detect.HasUDIFTrailer(byteReaderAt(data), r.Size) {
				s.commit(func() {
					s.findings = append(s.findings, Finding{ID: "udif-trailer", Title: "Executable that is also a disk image",
						Detail:   "This file starts like an executable but ends with a disk image trailer, so it both runs and mounts. Tools that look at only one side miss the other.",
						Severity: Medium, Category: "defense-evasion"})
				})
			}
			if err != nil {
				s.commit(func() {
					s.findings = append(s.findings, Finding{ID: "malformed-header", Title: "Malformed " + r.Format + " headers",
						Detail:   "The file claims to be an executable but its headers do not parse. This breaks analysis tools and is sometimes deliberate.",
						Severity: Medium, Category: "structure", Evidence: []string{err.Error()}})
				})
				return err
			}
			s.commit(func() { s.format = fr })
			return nil
		}},
		{"toolchain", func(ctx context.Context) error {
			tc, fs := goToolchain(data)
			if tc != nil {
				s.commit(func() { r.Toolchain = *tc; s.goFinds = fs })
			}
			return nil
		}},
	}

	// OS signature verification spawns a process / walks a cert chain, so
	// it runs concurrently with parsing instead of after it.
	if e.opt.VerifySignatures && !meta.SkipVerify && ((runtime.GOOS == "darwin" && (format == detect.MachO || format == detect.MachOFat)) ||
		(runtime.GOOS == "windows" && format == detect.PE)) {
		tasks = append(tasks, task{"signature verify", func(ctx context.Context) error {
			ok, detail, conclusive, err := platformVerify(ctx, path)
			if err != nil {
				return err
			}
			s.commit(func() {
				if conclusive {
					s.verified = &ok
				}
				s.verifyDetail = detail
			})
			return nil
		}})
	}

	timings := make([]Timing, len(tasks))
	for i, t := range tasks {
		timings[i] = Timing{Name: t.name, Status: "timeout"}
	}
	var wg sync.WaitGroup
	for i, t := range tasks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			status, msg := "ok", ""
			func() {
				defer func() {
					if p := recover(); p != nil {
						status, msg = "error", fmt.Sprint("panic: ", p)
						s.commit(func() {
							s.findings = append(s.findings, Finding{ID: "parser-crash", Title: "File crashed a parser",
								Detail: "Crafted headers that crash analysis tools are an anti-analysis technique.", Severity: Medium,
								Category: "structure", Evidence: []string{t.name + ": " + msg}})
						})
					}
				}()
				if err := t.fn(ctx); err != nil {
					if ctx.Err() != nil {
						status = "timeout"
					} else {
						status, msg = "error", err.Error()
					}
				}
			}()
			s.commit(func() { timings[i] = Timing{Name: t.name, Duration: time.Since(t0), Status: status, Error: msg} })
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		mf.Close()
		close(released)
	case <-ctx.Done():
		// Keep the mapping alive until stragglers return; unmapping under
		// a running parser would fault the whole process.
		go func() { <-done; mf.Close(); close(released) }()
	}
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	for _, t := range timings {
		if t.Status == "timeout" {
			r.Truncated = true
		}
	}
	r.Timings = timings
	e.correlate(s, format)
	r.AnalyzedAt = time.Now()
	r.Elapsed = time.Since(start)
	return r, released
}

// correlate turns raw task output into findings, a score and a verdict.
func (e *Engine) correlate(s *session, format detect.Format) {
	r := s.r
	fs := append([]Finding{}, s.findings...)
	if format != detect.Unknown {
		fs = append(fs, filenameFindings(r.FileName, format)...)
	}
	fs = append(fs, s.goFinds...)
	installer := false

	if c := s.content; c != nil {
		r.Entropy = entropy(&c.hist, uint64(r.Size))
		r.EntropyMap, r.EntropyBlock = c.blocks, c.blockSize
		r.Strings = Strings{Total: c.strings, URLs: sortedKeys(c.iocs.urls), IPs: sortedKeys(c.iocs.ips),
			Onions: sortedKeys(c.iocs.onions), Crypto: sortedKeys(c.iocs.crypto)}

		// Rules: count distinct logical patterns per rule.
		matched := make([]map[int32]bool, len(e.rules.rules))
		for pid, n := range c.hits {
			if n == 0 {
				continue
			}
			ri := e.rules.pidRule[pid]
			if matched[ri] == nil {
				matched[ri] = map[int32]bool{}
			}
			matched[ri][e.rules.pidLog[pid]] = true
		}
		for ri, m := range matched {
			rule := e.rules.rules[ri]
			if len(m) == 0 || len(m) < max(rule.Min, 1) {
				continue
			}
			var ev []string
			for li := range m {
				ev = append(ev, e.rules.logText[ri][li])
			}
			sort.Strings(ev)
			if rule.Category == CategoryToolchain {
				r.Toolchain.Notes = append(r.Toolchain.Notes, rule.ID)
				if strings.Contains(rule.ID, "installer") {
					installer = true
				}
				continue
			}
			sev := rule.Severity
			if rule.EscalateAt > 0 && len(m) >= rule.EscalateAt {
				sev = rule.EscalateTo
			}
			r.RuleHits = append(r.RuleHits, RuleHit{Rule: rule.ID, Matches: ev, Severity: sev})
			fs = append(fs, Finding{ID: rule.ID, Title: rule.Title, Detail: rule.Description, Severity: sev, Category: rule.Category, Evidence: ev})
		}
		sort.Strings(r.Toolchain.Notes)

		// IOCs
		if len(r.Strings.Onions) > 0 {
			fs = append(fs, Finding{ID: "ioc-onion", Title: "Tor hidden-service addresses", Severity: Medium, Category: "command-and-control", Evidence: r.Strings.Onions})
		}
		if len(r.Strings.Crypto) > 0 {
			fs = append(fs, Finding{ID: "ioc-crypto", Title: "Hard-coded cryptocurrency addresses",
				Detail: "Typical of ransom notes and clipboard hijackers that swap copied wallet addresses.", Severity: Medium, Category: "impact", Evidence: r.Strings.Crypto})
		}
		var rawIPURLs []string
		for _, u := range r.Strings.URLs {
			if _, ok := parseIPv4([]byte(urlHost(u))); ok {
				rawIPURLs = append(rawIPURLs, u)
			}
		}
		if len(rawIPURLs) > 0 {
			fs = append(fs, Finding{ID: "ioc-ip-url", Title: "URLs pointing at raw IP addresses",
				Detail: "Legitimate software talks to domain names; bare IPs are typical of C2 servers and payload hosts.", Severity: Medium, Category: "command-and-control", Evidence: rawIPURLs})
		}
		if len(r.Strings.IPs) > 0 {
			fs = append(fs, Finding{ID: "ioc-ip", Title: "Hard-coded public IP addresses", Severity: Info, Category: "network", Evidence: r.Strings.IPs})
		}
	}

	if f := s.format; f != nil {
		r.Slices = f.slices
		r.Signature = f.sig
		if r.Signature.Present && s.verifyDetail != "" {
			r.Signature.Verified, r.Signature.VerifyDetail = s.verified, s.verifyDetail
		}
		r.Hashes.Imphash = f.imphash
		r.Overlay = f.overlay
		fs = append(fs, f.findings...)
		names := map[string]bool{}
		for _, sl := range f.slices {
			r.Arches = append(r.Arches, sl.Arch)
			for _, im := range sl.Imports {
				names[im.Name] = true
			}
		}
		fs = append(fs, apiFindings(names)...)
		if v := r.Signature.Verified; v != nil && !*v && r.Signature.Present {
			sev := High
			if r.Signature.AdHoc {
				sev = Medium
			}
			fs = append(fs, Finding{ID: "sig-invalid", Title: "Code signature does not verify",
				Detail: "The file was modified after signing, or the signature is forged.", Severity: sev, Category: "signature",
				Evidence: []string{r.Signature.VerifyDetail}})
		}
	}

	// Browser engines (Chromium, CEF, Electron) legitimately manage browser
	// profiles and register global hotkeys. Only these inherent findings are
	// demoted; multi-browser and wallet harvesting still count in full.
	if hasNote(r.Toolchain.Notes, "Chromium") || hasNote(r.Toolchain.Notes, "Electron") {
		for i := range fs {
			switch fs[i].ID {
			case "stealer-cred-files", "api-keylogging", "api-priv-exec-mac":
				fs[i].Severity = Info
				fs[i].Detail = strings.TrimSpace(fs[i].Detail + " Expected in an embedded Chromium browser engine.")
			}
		}
	}

	if r.Entropy > 7.2 && r.Size > 32<<10 {
		sev := Medium
		// Installers and bundled-Python apps legitimately carry a big
		// compressed payload.
		imports := 0
		for _, sl := range r.Slices {
			imports = max(imports, len(sl.Imports))
		}
		switch {
		case installer || hasNote(r.Toolchain.Notes, "PyInstaller") || hasNote(r.Toolchain.Notes, "Nuitka"):
			sev = Info
		case imports >= 20:
			// A real import table means the code itself is not packed;
			// the entropy comes from embedded compressed assets.
			sev = Low
		}
		fs = append(fs, Finding{ID: "high-entropy", Title: "Very high overall entropy",
			Detail:   "Most of the file is compressed or encrypted data, hiding its real content from inspection.",
			Severity: sev, Category: "packer", Evidence: []string{fmt.Sprintf("%.2f bits/byte", r.Entropy)}})
	}

	if r.Truncated {
		fs = append(fs, Finding{ID: "truncated", Title: "Analysis hit the time budget",
			Detail: "Some checks did not finish; the verdict is based on partial results.", Severity: Info, Category: "engine"})
	}
	r.Findings = fs
	e.Finalize(r)
}

// Finalize applies hash lists, merges duplicate findings and computes the
// score and verdict from r.Findings and r.Signature. Container inspection
// calls it after assembling a report from many files.
func (e *Engine) Finalize(r *Report) {
	fs := r.Findings
	if note, ok := e.opt.Blocklist.Lookup(r.Hashes.SHA256); ok {
		fs = append(fs, Finding{ID: "hash-blocklist", Title: "SHA-256 is on the blocklist", Severity: Critical, Category: "reputation", Evidence: []string{note}})
	}
	r.Findings = dedupe(fs)
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	score(r, e.opt.Allowlist)
}

// Blocklisted reports whether a hash is on the blocklist (for files inside
// containers, which are not finalised individually).
func (e *Engine) Blocklisted(sha string) (string, bool) { return e.opt.Blocklist.Lookup(sha) }

// HashFile computes MD5, SHA-1 and SHA-256 of a file concurrently.
func HashFile(ctx context.Context, path string) (Hashes, error) {
	mf, err := mapfile.Open(path)
	if err != nil {
		return Hashes{}, err
	}
	defer mf.Close()
	var h Hashes
	var wg sync.WaitGroup
	for _, x := range []struct {
		h   hash.Hash
		dst *string
	}{{sha256.New(), &h.SHA256}, {sha1.New(), &h.SHA1}, {md5.New(), &h.MD5}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for off := 0; off < len(mf.Data); off += 4 << 20 {
				if ctx.Err() != nil {
					return
				}
				x.h.Write(mf.Data[off:min(off+4<<20, len(mf.Data))])
			}
			*x.dst = hex.EncodeToString(x.h.Sum(nil))
		}()
	}
	wg.Wait()
	return h, ctx.Err()
}

func hasNote(notes []string, prefix string) bool {
	for _, n := range notes {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return false
}

// dedupe merges findings with the same ID (e.g. per-slice findings in a
// universal binary), keeping the highest severity and all evidence.
func dedupe(fs []Finding) []Finding {
	idx := map[string]int{}
	var out []Finding
	for _, f := range fs {
		if i, ok := idx[f.ID]; ok {
			if f.Severity > out[i].Severity {
				out[i].Severity = f.Severity
			}
			for _, ev := range f.Evidence {
				if !contains(out[i].Evidence, ev) {
					out[i].Evidence = append(out[i].Evidence, ev)
				}
			}
			continue
		}
		idx[f.ID] = len(out)
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity > out[j].Severity })
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// FinalizeContainer scores a disk image or installer. Summing every
// finding of every contained file would make large, legitimate apps (dozens
// of frameworks) look worse than a small malicious one, so the score is the
// container's own findings plus its single worst file.
func (e *Engine) FinalizeContainer(r *Report, own, lifted []Finding, worstFile int) {
	if note, ok := e.opt.Blocklist.Lookup(r.Hashes.SHA256); ok {
		own = append(own, Finding{ID: "hash-blocklist", Title: "SHA-256 is on the blocklist", Severity: Critical, Category: "reputation", Evidence: []string{note}})
	}
	total := worstFile
	for _, f := range dedupe(own) {
		total += f.Severity.weight()
	}
	r.Findings = dedupe(append(own, lifted...))
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	applyScore(r, total, e.opt.Allowlist)
}

func score(r *Report, allow *HashList) {
	total := 0
	for _, f := range r.Findings {
		total += f.Severity.weight()
	}
	applyScore(r, total, allow)
}

func applyScore(r *Report, total int, allow *HashList) {
	maxSev := Info
	counts := map[Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
		if f.Severity > maxSev {
			maxSev = f.Severity
		}
	}
	sig := r.Signature
	trustedSigner := sig.Verified != nil && *sig.Verified && !sig.AdHoc && sig.Signer != ""
	if trustedSigner {
		total -= 20
		if sig.Notarized { // Apple scanned it and can revoke it
			total -= 10
		}
	}
	total = max(0, min(100, total))
	r.Score = total
	switch {
	case total >= 45 || maxSev == Critical:
		r.Verdict = VerdictMalicious
	case total >= 15:
		r.Verdict = VerdictSuspicious
	default:
		r.Verdict = VerdictClean
	}
	// A verified identity caps the verdict: signed malware exists, but a
	// heuristic alone should not brand a validly signed binary as malicious.
	if trustedSigner && r.Verdict == VerdictMalicious && maxSev < Critical {
		r.Verdict = VerdictSuspicious
	}
	if note, ok := allow.Lookup(r.Hashes.SHA256); ok {
		r.Verdict, r.Score = VerdictClean, 0
		r.Findings = append([]Finding{{ID: "hash-allowlist", Title: "SHA-256 is on your allowlist", Severity: Info, Category: "reputation", Evidence: []string{note}}}, r.Findings...)
	}

	var parts []string
	for sev := Critical; sev >= Low; sev-- {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	var titles []string
	for _, f := range r.Findings {
		if f.Severity >= Medium && len(titles) < 3 {
			titles = append(titles, f.Title)
		}
	}
	switch {
	case len(parts) == 0:
		r.Summary = "No suspicious indicators found."
	case len(titles) > 0:
		r.Summary = strings.Join(parts, ", ") + " — " + strings.Join(titles, "; ")
	default:
		r.Summary = strings.Join(parts, ", ") + " finding(s), none significant."
	}
}
