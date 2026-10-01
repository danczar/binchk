package container

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/danczar/binchk/internal/analyze"
	"github.com/danczar/binchk/internal/detect"
)

var plistEntry = regexp.MustCompile(`<key>(dev-entry|mount-point)</key>\s*<string>([^<]*)</string>`)

// attach mounts the image read-only, invisible to Finder, without
// auto-opening anything, and without verifying checksums (speed).
// -stdinpass with empty stdin makes encrypted images fail immediately
// instead of popping a password dialog.
//
// hdiutil is used because it works on every supported macOS; the pure-Go
// UDIF reader can replace it later without changing callers.
func attach(ctx context.Context, img string) (mnt, dev, parent string, err error) {
	parent, err = os.MkdirTemp("", "binchk-mnt-")
	if err != nil {
		return "", "", "", err
	}
	// hdiutil reports resolved paths (/private/var/...); match them.
	if real, err := filepath.EvalSymlinks(parent); err == nil {
		parent = real
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen",
		"-noverify", "-noautofsck", "-stdinpass", "-plist", "-mountrandom", parent, img)
	cmd.Stdin = strings.NewReader("")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	for _, m := range plistEntry.FindAllStringSubmatch(string(out), -1) {
		switch m[1] {
		case "dev-entry":
			// the whole-disk node is the shortest (/dev/disk6 vs /dev/disk6s1)
			if dev == "" || len(m[2]) < len(dev) {
				dev = m[2]
			}
		case "mount-point":
			if mnt == "" {
				mnt = m[2]
			}
		}
	}
	if err != nil {
		if dev != "" {
			detach(dev)
		}
		os.Remove(parent)
		msg := strings.TrimSpace(stderr.String())
		if i := strings.LastIndex(msg, "hdiutil: "); i >= 0 {
			msg = msg[i+len("hdiutil: "):]
		}
		if msg == "" {
			msg = err.Error()
		}
		return "", "", "", errors.New(msg)
	}
	return mnt, dev, parent, nil
}

func detach(dev string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if exec.CommandContext(ctx, "/usr/bin/hdiutil", "detach", "-quiet", dev).Run() != nil {
		exec.CommandContext(ctx, "/usr/bin/hdiutil", "detach", "-quiet", "-force", dev).Run()
	}
}

// inspectDMG mounts and walks the image at path. Callers analyse the image
// file's own bytes separately (analyzeSelf), mounted or not.
func (in *inspector) inspectDMG(path string) {
	// The image file's own Gatekeeper verdict: ~0.2 s, reads no contents,
	// and tells us whether the vendor signed and notarized the download.
	// It is the trust fallback when a huge app cannot be verified in time.
	in.imageChecked = make(chan struct{})
	in.goTask(func() {
		defer close(in.imageChecked)
		t0 := time.Now()
		out, _ := exec.CommandContext(in.ctx, "/usr/sbin/spctl", "--assess", "--type", "open",
			"--context", "context:primary-signature", "-vv", path).CombinedOutput()
		in.timed("Gatekeeper (disk image)", t0, in.ctx.Err())
		var g gkResult
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			switch {
			case strings.HasPrefix(line, "source="):
				g.source = strings.TrimPrefix(line, "source=")
			case strings.HasPrefix(line, "origin="):
				g.origin = strings.TrimPrefix(line, "origin=")
			case strings.HasSuffix(line, ": accepted"):
				g.accepted = true
			case strings.HasPrefix(line, path+": "):
				g.raw = strings.TrimPrefix(line, path+": ")
			}
		}
		switch {
		case g.accepted && strings.Contains(g.source, "Notarized"):
			ok := true
			in.note("The disk image itself is signed and notarized: %s.", g.origin)
			in.mu.Lock()
			in.imageSig = &analyze.Signature{Present: true, Kind: "Signed disk image", Signer: g.origin,
				Verified: &ok, VerifyDetail: "spctl: accepted — " + g.source, Gatekeeper: "accepted — " + g.source, Notarized: true}
			if m := reTeam.FindStringSubmatch(g.origin); m != nil {
				in.imageSig.TeamID = m[1]
			}
			in.mu.Unlock()
		case strings.Contains(g.raw, "REVOKED"):
			in.add(analyze.Finding{ID: "cert-revoked", Title: "Signing certificate has been revoked",
				Detail:   "Apple revoked the certificate this disk image was signed with. This copy should not be trusted; download a current version from the vendor.",
				Severity: analyze.High, Category: "signature", Evidence: []string{filepath.Base(path) + ": " + g.raw}})
		}
	})
	t0 := time.Now()
	mnt, dev, parent, err := attach(in.ctx, path)
	in.timed("mount (hdiutil, read-only)", t0, err)
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "Authentication error"):
			in.add(analyze.Finding{ID: "dmg-encrypted", Title: "Password-protected disk image",
				Detail:   "Its contents cannot be inspected. Encrypted images are a common way to slip malware past scanners, with the password supplied in the message or web page.",
				Severity: analyze.Medium, Category: "defense-evasion"})
		case strings.Contains(msg, "cancel") || strings.Contains(strings.ToLower(msg), "licen"):
			in.note("The image shows a licence agreement when mounted; binchk does not accept it on your behalf, so its contents were not inspected.")
		default:
			in.add(analyze.Finding{ID: "dmg-unreadable", Title: "Disk image could not be opened",
				Severity: analyze.Low, Category: "structure", Evidence: []string{msg}})
		}
		return
	}
	// If the image was already attached (e.g. Safari auto-opened it), hdiutil
	// returns the existing mount: inspect it, but never eject the user's
	// volume — only detach mounts binchk created under its own directory.
	owned := mnt == "" || strings.HasPrefix(mnt, parent+string(filepath.Separator))
	in.onRelease(func() {
		if owned {
			detach(dev)
		}
		os.Remove(parent)
	})
	if !owned {
		in.note("The image was already mounted by another app; binchk inspected that mount and left it attached.")
	}
	if mnt == "" {
		in.add(analyze.Finding{ID: "dmg-no-volume", Title: "Disk image has no mountable volume", Severity: analyze.Low, Category: "structure"})
		return
	}
	in.c.Volume = filepath.Base(mnt)
	in.walkVolume(mnt, "", 0)

	// A script shipped next to an app that strips quarantine or disables
	// Gatekeeper is the "Fix damaged app" trick Mac stealers use: on its own
	// the script is a few lines, in context it is the attack.
	in.onFinish(func() {
		in.mu.Lock()
		defer in.mu.Unlock()
		var ev []string
		for _, f := range in.c.Files {
			if f.Kind != "script" {
				continue
			}
			for _, fd := range f.Findings {
				if fd.ID == "evasion-macos" {
					for _, e := range fd.Evidence {
						ev = append(ev, f.Path+": "+e)
					}
				}
			}
		}
		if len(ev) > 0 {
			in.findings = append(in.findings, analyze.Finding{ID: "dmg-gatekeeper-bypass", Title: "Ships a script that switches off Gatekeeper",
				Detail:   "The disk image includes a script that removes the quarantine flag or disables Gatekeeper, so its app runs unchecked — the \"fix damaged app\" trick used by Mac infostealers.",
				Severity: analyze.High, Category: "defense-evasion", Evidence: ev})
		}
	})
}

var volumeNoise = map[string]bool{
	".background": true, ".fseventsd": true, ".Trashes": true, ".Spotlight-V100": true, ".DocumentRevisions-V100": true,
	".TemporaryItems": true, ".DS_Store": true, ".VolumeIcon.icns": true, ".HFS+ Private Directory Data\r": true,
	".journal": true, ".journal_info_block": true,
}

// walkVolume inspects a mounted image: apps and installers as units, loose
// executables and scripts individually.
func (in *inspector) walkVolume(dir, rel string, depth int) {
	entries, err := os.ReadDir(dir)
	if err != nil || depth > 4 {
		return
	}
	for _, e := range entries {
		name := e.Name()
		abs, r := filepath.Join(dir, name), filepath.Join(rel, name)
		if volumeNoise[name] || e.Type()&os.ModeSymlink != 0 {
			continue // symlinks: the usual "Applications" drop target
		}
		ext := strings.ToLower(filepath.Ext(name))
		if e.IsDir() {
			switch ext {
			case ".app":
				in.inspectApp(abs, r, true, false)
			case ".pkg", ".mpkg":
				in.note("%s is a legacy bundle-style package and was not inspected.", r)
			default:
				in.walkVolume(abs, r, depth+1)
			}
			continue
		}
		if !e.Type().IsRegular() {
			continue
		}
		hidden := strings.HasPrefix(name, ".")
		switch f := detect.SniffFile(abs); {
		case f == detect.InstallerPkg:
			in.inspectPkg(abs, r, false)
		case f == detect.DiskImage:
			in.add(analyze.Finding{ID: "dmg-nested", Title: "Disk image inside a disk image",
				Detail: "Nesting hides content from single-level inspection; the inner image was not opened.", Severity: analyze.Low,
				Category: "defense-evasion", Evidence: []string{r}})
			// The inner image is not mounted, but its bytes are still
			// analysed: a script or other runnable file with a forged
			// trailer must not escape inspection by looking like an image.
			if hidden {
				in.add(hiddenExec(r))
			}
			if isScriptName(name) || hasShebang(abs) {
				in.add(scriptToRun(r))
			}
			in.analyzeFile(abs, r, "nested image", fileSize(abs))
		case f != detect.Unknown:
			if hidden {
				in.add(hiddenExec(r))
			}
			in.analyzeFile(abs, r, "executable", fileSize(abs))
		case isScriptName(name) || hasShebang(abs):
			if hidden {
				in.add(hiddenExec(r))
			}
			in.add(scriptToRun(r))
			in.analyzeFile(abs, r, "script", fileSize(abs))
		}
	}
}

func scriptToRun(rel string) analyze.Finding {
	return analyze.Finding{ID: "dmg-script", Title: "Disk image contains a script to run",
		Detail:   "\"Double-click this to install\" scripts (.command, .sh) bypass Gatekeeper's app checks; fake installers use them to run commands directly.",
		Severity: analyze.Medium, Category: "execution", Evidence: []string{rel}}
}

func hiddenExec(rel string) analyze.Finding {
	return analyze.Finding{ID: "dmg-hidden-exec", Title: "Hidden executable in disk image",
		Detail:   "Dot-files are invisible in Finder; a hidden program next to a visible installer is a classic dropper pattern.",
		Severity: analyze.High, Category: "defense-evasion", Evidence: []string{rel}}
}
