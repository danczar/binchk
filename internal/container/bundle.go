package container

import (
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

func hasShebang(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	var b [2]byte
	n, _ := f.Read(b[:])
	return n == 2 && b[0] == '#' && b[1] == '!'
}

// addBundle registers a bundle whose properties are filled in as checks
// finish; keys keep their display order.
func (in *inspector) addBundle(rel, kind string, keys ...string) int {
	b := analyze.Bundle{Path: rel, Kind: kind}
	for _, k := range keys {
		b.Props = append(b.Props, analyze.KV{K: k})
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	in.c.Bundles = append(in.c.Bundles, b)
	return len(in.c.Bundles) - 1
}

func (in *inspector) setProp(idx int, k, v string) {
	in.mu.Lock()
	defer in.mu.Unlock()
	b := &in.c.Bundles[idx]
	for i := range b.Props {
		if b.Props[i].K == k {
			b.Props[i].V = v
			return
		}
	}
	b.Props = append(b.Props, analyze.KV{K: k, V: v})
}

// inspectApp examines an .app bundle: metadata, Apple's seal and Gatekeeper
// verdicts, and the executables inside it.
//
// assess runs Gatekeeper on the app; apps inside installer payloads are not
// assessed individually because macOS judges the package, not its contents.
// partial marks an app whose files were not all extracted (payload limit),
// so seal and completeness checks would be meaningless.
func (in *inspector) inspectApp(abs, rel string, assess, partial bool) {
	idx := in.addBundle(rel, "Application", "Bundle ID", "Version", "Signed by", "Team ID", "Code signature", "Gatekeeper")
	info, _ := readPlist(in.ctx, filepath.Join(abs, "Contents", "Info.plist"))
	in.setProp(idx, "Bundle ID", info["CFBundleIdentifier"])
	v := info["CFBundleShortVersionString"]
	if b := info["CFBundleVersion"]; b != "" && b != v {
		v = strings.TrimSpace(v + " (" + b + ")")
	}
	in.setProp(idx, "Version", v)
	if m := info["LSMinimumSystemVersion"]; m != "" {
		in.setProp(idx, "Minimum macOS", m)
	}
	if info["LSUIElement"] == "true" || info["LSUIElement"] == "1" || info["LSBackgroundOnly"] == "true" {
		in.setProp(idx, "Dock icon", "none (runs in the background / menu bar)")
	}
	exe := info["CFBundleExecutable"]
	mainPath := filepath.Join(abs, "Contents", "MacOS", exe)

	// Apple's verdicts start first: on big apps they are the slowest part.
	var (
		sigMu    sync.Mutex
		sig      = analyze.Signature{Kind: "Apple code signature (app bundle)"}
		sealOK   *bool
		sealMsg  string
		unsigned bool
	)
	in.goTask(func() {
		t0 := time.Now()
		m, err := codesignInfo(in.ctx, abs)
		in.timed("codesign -dvv "+rel, t0, err)
		if err != nil {
			return
		}
		sigMu.Lock()
		defer sigMu.Unlock()
		auth := m["Authority"]
		if len(auth) > 0 {
			sig.Signer = auth[0]
			in.setProp(idx, "Signed by", auth[0])
		}
		if len(auth) > 1 {
			sig.Issuer = auth[1]
		}
		if t := m["TeamIdentifier"]; len(t) > 0 && t[0] != "not set" {
			sig.TeamID = t[0]
			in.setProp(idx, "Team ID", t[0])
		}
		if id := m["Identifier"]; len(id) > 0 {
			sig.Identifier = id[0]
		}
		if f := m["flags"]; len(f) > 0 {
			sig.Flags = []string{f[0]}
			sig.Hardened = strings.Contains(f[0], "runtime")
		}
		sig.AdHoc = len(auth) == 0
	})
	// A signed, notarized disk image already seals every byte of the app
	// inside it; the deep checks below read the whole bundle (seconds for
	// big apps) and would add nothing, so they are skipped in that case.
	coveredByImage := func() bool {
		if assess && in.imageNotarized() {
			in.setProp(idx, "Code signature", "covered by the notarized disk image's signature")
			in.setProp(idx, "Gatekeeper", "covered by the notarized disk image")
			return true
		}
		return false
	}
	if partial {
		in.setProp(idx, "Code signature", "not checked (app only partly extracted)")
	} else {
		in.goTask(func() {
			if coveredByImage() {
				return
			}
			t0 := time.Now()
			ok, uns, detail, err := bundleVerify(in.ctx, abs)
			in.timed("codesign --verify --deep "+rel, t0, err)
			if err != nil {
				in.setProp(idx, "Code signature", "not checked ("+err.Error()+")")
				return
			}
			sigMu.Lock()
			sealOK, sealMsg, unsigned = &ok, detail, uns
			sigMu.Unlock()
		})
	}
	if !assess || partial {
		in.setProp(idx, "Gatekeeper", "covered by the installer package's assessment")
	} else {
		in.goTask(func() {
			if assess && in.imageNotarized() {
				return
			}
			t0 := time.Now()
			g, err := gatekeeper(in.ctx, abs, "execute")
			in.timed("Gatekeeper (spctl) "+rel, t0, err)
			if err != nil {
				in.setProp(idx, "Gatekeeper", "not assessed ("+err.Error()+")")
				return
			}
			sigMu.Lock()
			defer sigMu.Unlock()
			in.gatekeeperFindings(idx, rel, g, &sig)
		})
	}

	// Structure checks and the file walk.
	if !partial {
		if exe == "" || fileSize(mainPath) == 0 {
			in.add(analyze.Finding{ID: "app-no-executable", Title: "App has no valid main executable",
				Severity: analyze.Medium, Category: "structure", Evidence: []string{rel}})
		} else if hasShebang(mainPath) {
			in.add(analyze.Finding{ID: "app-script-main", Title: "App's main executable is a script",
				Detail:   "The app is a thin wrapper that runs a shell/Python script — common in droppers, and it escapes most binary checks.",
				Severity: analyze.Medium, Category: "execution", Evidence: []string{filepath.Join(rel, "Contents/MacOS", exe)}})
		}
	}
	if exe == "applet" && fileSize(filepath.Join(abs, "Contents/Resources/Scripts/main.scpt")) > 0 {
		in.add(analyze.Finding{ID: "app-applescript", Title: "AppleScript applet",
			Detail:   "The app is a compiled AppleScript. Mac infostealers are frequently delivered this way.",
			Severity: analyze.Low, Category: "execution", Evidence: []string{rel}})
	}
	in.goTask(func() {
		t0 := time.Now()
		in.bundleCode(abs, rel, mainPath, func(c cand) { in.analyzeFile(c.abs, c.rel, c.kind, c.size) })
		in.timed("scan bundle "+rel, t0, in.ctx.Err())
	})

	in.onFinish(func() {
		sigMu.Lock()
		defer sigMu.Unlock()
		switch {
		case sealOK == nil:
		case *sealOK:
			sig.Present, sig.Verified = true, sealOK
			sig.VerifyDetail = "codesign --deep: " + sealMsg
			if sig.AdHoc {
				in.setProp(idx, "Code signature", "sealed ad-hoc — no developer identity")
			} else {
				in.setProp(idx, "Code signature", "valid (whole bundle sealed)")
			}
		case unsigned:
			in.setProp(idx, "Code signature", "not signed")
			in.add(analyze.Finding{ID: "macho-unsigned", Title: "App is not code-signed",
				Detail: "Legitimate Mac software is signed by an identified developer.", Severity: analyze.Medium,
				Category: "signature", Evidence: []string{rel}})
		default:
			sig.Present, sig.Verified = true, sealOK
			sig.VerifyDetail = "codesign --deep: " + sealMsg
			in.setProp(idx, "Code signature", "INVALID — "+sealMsg)
			// A broken Developer ID seal means tampering; a broken ad-hoc
			// seal is just sloppy packaging.
			sev := analyze.High
			if sig.AdHoc {
				sev = analyze.Medium
			}
			in.add(analyze.Finding{ID: "bundle-seal-broken", Title: "App bundle's signature is broken",
				Detail:   "Files inside the app were changed after it was signed, or the signature is forged.",
				Severity: sev, Category: "signature", Evidence: []string{rel + ": " + sealMsg}})
		}
		if sig.Signer != "" {
			sig.Present = true
		}
		// A revoked certificate earns no trust, however valid the seal.
		if strings.Contains(sig.Gatekeeper, "revoked") {
			f := false
			sig.Verified = &f
			sig.VerifyDetail = "Gatekeeper: " + sig.Gatekeeper
		}
		in.mu.Lock()
		if in.sig == nil {
			s := sig
			in.sig = &s
		}
		in.mu.Unlock()
	})
}

type cand struct {
	abs, rel, kind string
	size           int64
}

// codeExts are files worth sniffing even without an execute bit.
var codeExts = map[string]bool{".dylib": true, ".so": true, ".node": true, ".bundle": true, ".plugin": true, ".scpt": true}

// bundleCode emits the executables in a bundle: the main executable at once,
// then the rest smallest-first once the walk completes. On a compressed disk
// image reads are bound by the image decompressor (~100 MB/s), so ordering
// by size analyses the most files — helpers, plug-ins and small injected
// dylibs — before the huge vendor frameworks. Only files with an execute
// bit or a code extension are opened: Electron apps hold tens of thousands
// of files, and each open reads (and on a disk image, decompresses) data.
func (in *inspector) bundleCode(abs, rel, mainPath string, emitNow func(cand)) {
	var found []cand
	emit := func(c cand) { found = append(found, c) }
	defer func() {
		sort.Slice(found, func(i, j int) bool { return found[i].size < found[j].size })
		for _, c := range found {
			emitNow(c)
		}
	}()
	seen := map[string]bool{}
	visit := func(p string, d fs.DirEntry) {
		if seen[p] {
			return
		}
		seen[p] = true
		st, err := d.Info()
		if err != nil {
			return
		}
		r := filepath.Join(rel, strings.TrimPrefix(p, abs+string(filepath.Separator)))
		switch {
		case p == mainPath:
		case st.Mode()&0o111 == 0 && !codeExts[strings.ToLower(filepath.Ext(p))]:
		case strings.HasSuffix(p, "Contents/Resources/Scripts/main.scpt"):
			emit(cand{p, r, "AppleScript", st.Size()})
		case detect.SniffFile(p) != detect.Unknown:
			emit(cand{p, r, "bundled code", st.Size()})
		case strings.Contains(p, "/Contents/MacOS/") && hasShebang(p):
			emit(cand{p, r, "script", st.Size()})
		}
	}
	if st, err := os.Stat(mainPath); err == nil && st.Mode().IsRegular() {
		seen[mainPath] = true
		emitNow(cand{mainPath, filepath.Join(rel, strings.TrimPrefix(mainPath, abs+string(filepath.Separator))), "main executable", st.Size()})
	}
	roots := []string{"Contents/MacOS", "Contents/Frameworks", "Contents/Library", "Contents/PlugIns",
		"Contents/XPCServices", "Contents/Helpers", "Contents/SharedSupport", ""}
	for _, sub := range roots {
		root := filepath.Join(abs, sub)
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if in.ctx.Err() != nil {
				return filepath.SkipAll
			}
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if strings.HasSuffix(p, ".dSYM") || (sub == "" && p != root && seen[p]) {
					return filepath.SkipDir
				}
				if sub != "" {
					seen[p] = true // already walked; skip in the final pass
				}
				return nil
			}
			if d.Type().IsRegular() {
				visit(p, d)
			}
			return nil
		})
		if sub != "" {
			seen[root] = true
		}
	}
}

// gatekeeperFindings maps an spctl verdict to findings and properties.
func (in *inspector) gatekeeperFindings(idx int, rel string, g gkResult, sig *analyze.Signature) {
	switch {
	case g.accepted:
		verdict := "accepted"
		if g.source != "" {
			verdict += " — " + g.source
		}
		sig.Gatekeeper = verdict
		sig.Notarized = strings.Contains(g.source, "Notarized") || g.source == "Apple System" || g.source == "Mac App Store"
		in.setProp(idx, "Gatekeeper", verdict)
	case strings.Contains(g.source, "Unnotarized"):
		sig.Gatekeeper = "rejected — " + g.source
		in.setProp(idx, "Gatekeeper", sig.Gatekeeper)
		in.add(analyze.Finding{ID: "not-notarized", Title: "Not notarized by Apple",
			Detail:   "Apple has not scanned this software, so macOS will block it by default. Legitimate developers notarize their releases.",
			Severity: analyze.Medium, Category: "signature", Evidence: []string{rel}})
	case strings.Contains(g.raw, "REVOKED"):
		sig.Gatekeeper = "rejected — certificate revoked"
		in.setProp(idx, "Gatekeeper", sig.Gatekeeper)
		in.add(analyze.Finding{ID: "cert-revoked", Title: "Signing certificate has been revoked",
			Detail:   "Apple revoked the certificate this was signed with — after a compromise or abuse. This copy should not be trusted; download a current version from the vendor.",
			Severity: analyze.High, Category: "signature", Evidence: []string{rel + ": " + g.raw}})
	case strings.Contains(g.source, "Notarized"):
		// Rejected despite notarization: Apple withdrew the ticket, which it
		// does for software found to be malicious.
		sig.Gatekeeper = "rejected — " + g.source
		in.setProp(idx, "Gatekeeper", sig.Gatekeeper)
		in.add(analyze.Finding{ID: "notarization-revoked", Title: "Apple has withdrawn this software's notarization",
			Detail:   "Gatekeeper rejects it although it was notarized; Apple does this when notarized software turns out to be malicious.",
			Severity: analyze.High, Category: "signature", Evidence: []string{rel + ": " + g.source}})
	default:
		why := g.source
		if why == "" {
			why = g.raw
		}
		if why == "" || why == "rejected" {
			why = "no usable signature"
		}
		sig.Gatekeeper = "rejected — " + why
		in.setProp(idx, "Gatekeeper", sig.Gatekeeper)
		in.add(analyze.Finding{ID: "gatekeeper-rejected", Title: "macOS Gatekeeper would block this",
			Detail:   "It has no valid Developer ID signature. Malware delivered this way tells you to right-click → Open, use Terminal, or run xattr to get around the block. Don't.",
			Severity: analyze.Medium, Category: "signature", Evidence: []string{rel + ": " + why}})
	}
}
