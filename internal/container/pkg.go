package container

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/danczar/binchk/internal/analyze"
	"github.com/danczar/binchk/internal/detect"
	"github.com/danczar/binchk/internal/xar"
)

var (
	reInstallLoc = regexp.MustCompile(`install-location="([^"]*)"`)
	reIdentifier = regexp.MustCompile(`<pkg-info[^>]*\sidentifier="([^"]*)"`)
	reTeam       = regexp.MustCompile(`\(([A-Z0-9]{10})\)\s*$`)
)

// inspectPkg examines a flat installer package using binchk's own xar
// reader (any OS); Apple's signature and notarization verdicts are added on
// macOS. top marks a package that is the file being analysed itself.
func (in *inspector) inspectPkg(abs, rel string, top bool) {
	idx := in.addBundle(rel, "Installer package", "Identifier", "Signed by", "Signature", "Notarization", "Gatekeeper",
		"Install location", "Install scripts", "Payload")
	t0 := time.Now()
	a, err := xar.Open(abs)
	in.timed("read package "+rel, t0, err)
	if err != nil {
		in.add(analyze.Finding{ID: "pkg-unreadable", Title: "Installer package could not be read",
			Severity: analyze.Low, Category: "structure", Evidence: []string{rel + ": " + err.Error()}})
		return
	}
	var sig analyze.Signature
	sig.Kind = "Installer package signature"
	if len(a.Certs) > 0 {
		sig.Present = true
		fillCert(&sig, a)
		in.setProp(idx, "Signed by", sig.Signer)
		in.setProp(idx, "Signature", "present (verified by pkgutil on macOS)")
	} else {
		in.setProp(idx, "Signature", "none")
		in.add(analyze.Finding{ID: "pkg-unsigned", Title: "Installer package is not signed",
			Detail:   "Installers run with administrator rights; legitimate ones are signed with a Developer ID Installer certificate.",
			Severity: analyze.Medium, Category: "signature", Evidence: []string{rel}})
	}

	tmp, err := os.MkdirTemp("", "binchk-pkg-")
	if err != nil {
		a.Close()
		return
	}
	in.onRelease(func() { os.RemoveAll(tmp) })

	// Distribution script and PackageInfo metadata.
	var ids, locs []string
	for _, e := range a.Entries {
		base := filepath.Base(e.Path)
		switch {
		case e.Path == "Distribution":
			b, _ := a.ReadAll(e, 4<<20)
			if strings.Contains(string(b), "system.run") {
				in.add(analyze.Finding{ID: "pkg-distribution-exec", Title: "Installer runs commands before installing",
					Detail:   "Its Distribution script calls system.run, executing programs as soon as the installer opens — before you click Install.",
					Severity: analyze.Medium, Category: "execution", Evidence: []string{rel + "/Distribution"}})
			}
			p := filepath.Join(tmp, "Distribution")
			if os.WriteFile(p, b, 0o600) == nil {
				in.analyzeFile(p, rel+"/Distribution", "installer script", int64(len(b)))
			}
		case base == "PackageInfo":
			b, _ := a.ReadAll(e, 1<<20)
			if m := reIdentifier.FindSubmatch(b); m != nil {
				ids = append(ids, string(m[1]))
			}
			if m := reInstallLoc.FindSubmatch(b); m != nil {
				locs = append(locs, string(m[1]))
			}
		}
	}
	in.setProp(idx, "Identifier", strings.Join(ids, ", "))
	in.setProp(idx, "Install location", strings.Join(locs, ", "))

	// Scripts and payloads are decompressed concurrently.
	var scriptNames []string
	in.goTask(func() {
		defer a.Close()
		var payloadNotes []string
		for _, e := range a.Entries {
			base := filepath.Base(e.Path)
			if base != "Scripts" && base != "Payload" || e.Type != "file" {
				continue
			}
			comp := strings.TrimSuffix(filepath.Dir(e.Path), ".")
			dst := filepath.Join(tmp, "x", comp, base)
			t0 := time.Now()
			n, err := extract(in, a, e, dst, base == "Payload")
			in.timed("extract "+filepath.Join(rel, e.Path), t0, err)
			if base == "Payload" {
				note := humanSize(n) + " extracted"
				if errors.Is(err, xar.ErrLimit) {
					note += " (stopped at limit)"
				} else if err != nil {
					note += " (" + err.Error() + ")"
				}
				payloadNotes = append(payloadNotes, note)
			}
			in.walkExtracted(dst, filepath.Join(rel, e.Path), base == "Scripts", err == nil, &scriptNames)
		}
		in.setProp(idx, "Payload", strings.Join(payloadNotes, "; "))
		in.mu.Lock()
		names := append([]string{}, scriptNames...)
		in.mu.Unlock()
		if len(names) > 0 {
			in.setProp(idx, "Install scripts", strings.Join(names, ", "))
			in.add(analyze.Finding{ID: "pkg-scripts", Title: "Runs install scripts as root",
				Detail:   "Pre/post-install scripts execute with full administrator rights. Common in legitimate installers, but they are where malicious installers do their work — see the script findings.",
				Severity: analyze.Low, Category: "execution", Evidence: names})
		} else {
			in.setProp(idx, "Install scripts", "none")
		}
	})

	// Apple's verdicts (macOS).
	in.goTask(func() {
		t0 := time.Now()
		ps, err := pkgSignature(in.ctx, abs)
		in.timed("pkgutil --check-signature "+rel, t0, err)
		if err != nil {
			if !supportsDMG {
				in.setProp(idx, "Notarization", "not checked (requires macOS)")
			}
			return
		}
		in.setProp(idx, "Signature", ps.status)
		in.setProp(idx, "Notarization", ps.notarization)
		ok := strings.HasPrefix(ps.status, "signed") && !strings.Contains(ps.status, "untrusted") &&
			!strings.Contains(ps.status, "revoked") && !strings.Contains(ps.status, "expired")
		in.mu.Lock()
		if sig.Present {
			sig.Verified = &ok
			sig.VerifyDetail = "pkgutil: " + ps.status
			sig.Notarized = strings.Contains(ps.notarization, "trusted")
		}
		in.mu.Unlock()
		if !ok && ps.status != "no signature" {
			in.add(analyze.Finding{ID: "pkg-sig-invalid", Title: "Installer signature is not trusted",
				Severity: analyze.High, Category: "signature", Evidence: []string{rel + ": " + ps.status}})
		}
	})
	in.goTask(func() {
		t0 := time.Now()
		g, err := gatekeeper(in.ctx, abs, "install")
		in.timed("Gatekeeper (spctl) "+rel, t0, err)
		if err != nil {
			in.setProp(idx, "Gatekeeper", "not assessed")
			return
		}
		in.mu.Lock()
		s := sig
		in.mu.Unlock()
		in.gatekeeperFindings(idx, rel, g, &s)
		in.mu.Lock()
		sig.Gatekeeper, sig.Notarized = s.Gatekeeper, sig.Notarized || s.Notarized
		in.mu.Unlock()
	})
	in.onFinish(func() {
		in.mu.Lock()
		defer in.mu.Unlock()
		if top && in.sig == nil {
			s := sig
			in.sig = &s
		}
	})
}

func fillCert(sig *analyze.Signature, a *xar.Archive) {
	var leaf = a.Certs[0]
	for _, c := range a.Certs {
		if !c.IsCA {
			leaf = c
			break
		}
	}
	sig.Signer = leaf.Subject.CommonName
	sig.Issuer = leaf.Issuer.CommonName
	sig.NotAfter = leaf.NotAfter.Format("2006-01-02")
	if len(leaf.Subject.OrganizationalUnit) > 0 {
		sig.TeamID = leaf.Subject.OrganizationalUnit[0]
	} else if m := reTeam.FindStringSubmatch(sig.Signer); m != nil {
		sig.TeamID = m[1]
	}
}

// extract decompresses a Scripts or Payload stream into dst.
func extract(in *inspector, a *xar.Archive, e xar.Entry, dst string, payload bool) (int64, error) {
	rc, err := a.Open(e)
	if err != nil {
		return 0, err
	}
	defer rc.Close()
	pr, err := xar.PayloadReader(rc)
	if err != nil {
		return 0, err
	}
	lim := xar.Limits{MaxBytes: 64 << 20, MaxEntries: 10000}
	if payload {
		lim = xar.Limits{MaxBytes: maxExpand, MaxEntries: 200000}
	}
	return xar.ExtractCPIO(in.ctx, pr, dst, lim)
}

// walkExtracted queues the interesting parts of an extracted Scripts or
// Payload tree: every script; apps as bundles; loose executables; launchd
// jobs and kernel extensions as findings.
func (in *inspector) walkExtracted(root, rel string, scripts, complete bool, scriptNames *[]string) {
	var daemons, kexts []string
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if in.ctx.Err() != nil {
			return filepath.SkipAll
		}
		if err != nil {
			return nil
		}
		sub := strings.TrimPrefix(p, root+string(filepath.Separator))
		r := filepath.Join(rel, sub)
		if d.IsDir() {
			switch strings.ToLower(filepath.Ext(p)) {
			case ".app":
				in.inspectApp(p, r, false, !complete)
				return filepath.SkipDir
			case ".dsym":
				return filepath.SkipDir
			case ".kext", ".systemextension":
				kexts = append(kexts, "/"+sub)
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		size := fileSize(p)
		switch {
		case scripts:
			in.mu.Lock()
			*scriptNames = append(*scriptNames, sub)
			in.mu.Unlock()
			in.analyzeFile(p, r, "install script", size)
		case strings.Contains(sub, "Library/LaunchDaemons/") || strings.Contains(sub, "Library/LaunchAgents/"):
			daemons = append(daemons, "/"+sub)
			in.analyzeFile(p, r, "launchd job", size)
		case detect.SniffFile(p) != detect.Unknown:
			in.analyzeFile(p, r, "installed program", size)
		case hasShebang(p):
			in.analyzeFile(p, r, "installed script", size)
		}
		return nil
	})
	if len(daemons) > 0 {
		in.add(analyze.Finding{ID: "pkg-launchd", Title: "Installs programs that start automatically",
			Detail:   "Launch daemons run as root at boot; launch agents run at every login. Normal for some software, and the standard persistence method for Mac malware.",
			Severity: analyze.Low, Category: "persistence", Evidence: daemons})
	}
	if len(kexts) > 0 {
		in.add(analyze.Finding{ID: "pkg-kext", Title: "Installs a kernel or system extension",
			Severity: analyze.Medium, Category: "privilege-escalation", Evidence: kexts})
	}
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return strings.TrimSuffix(strings.TrimSuffix(jsonNum(float64(n*10>>30)/10), ".0"), ".") + " GiB"
	case n >= 1<<20:
		return jsonNum(float64(n*10>>20)/10) + " MiB"
	case n >= 1<<10:
		return jsonNum(float64(n*10>>10)/10) + " KiB"
	}
	return jsonNum(float64(n)) + " B"
}
