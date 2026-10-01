package analyze

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A stealer must not be able to silence its credential-store finding by
// embedding the strings that identify a Chromium/Electron engine.
func TestEngineStringsDoNotDemoteStealer(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	payload := []byte("\x00Login Data\x00logins.json\x00key4.db\x00Web Data\x00Local State\x00Cookies.binarycookies\x00" +
		"chrome-extension://\x00chrome://version\x00Chromium Embedded Framework\x00electron.asar\x00ELECTRON_RUN_AS_NODE\x00")
	eng := newTestEngine(t, 10*time.Second)
	for _, tg := range targets {
		t.Run(tg.goos, func(t *testing.T) {
			path := goBuild(t, "benign", tg.goos, tg.goarch, "hello")
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			f.Write(payload)
			f.Close()
			// Standalone, and as a file inside a container.
			for _, meta := range []Meta{{}, {SkipVerify: true}, {SkipVerify: true, Sealed: true}} {
				r := eng.Analyze(context.Background(), path, meta)
				if !hasNote(r.Toolchain.Notes, "Chromium") || !hasNote(r.Toolchain.Notes, "Electron") {
					t.Fatalf("engine notes not set: %v", r.Toolchain.Notes)
				}
				if sev := findingIDs(r)["stealer-cred-files"]; sev < Medium {
					t.Errorf("SkipVerify=%v: stealer-cred-files = %v, want >= medium (%s %d)", meta.SkipVerify, sev, r.Verdict, r.Score)
				}
			}
		})
	}
}

func TestBrowserEngineGate(t *testing.T) {
	yes := true
	no := false
	engine := func(mod func(r *Report)) *Report {
		r := &Report{Format: "Mach-O", Size: 200 << 20,
			Signature: Signature{Present: true, Signer: "Developer ID Application: Example (ABCDE12345)", TeamID: "ABCDE12345", Verified: &yes},
			Slices:    []Slice{{ExportCount: 11000}}}
		if mod != nil {
			mod(r)
		}
		return r
	}
	cases := []struct {
		name    string
		r       *Report
		markers int
		sealed  bool
		fs      []Finding
		want    engineTrust
	}{
		{"verified signer", engine(nil), 3, false, nil, engineTrusted},
		{"one marker", engine(nil), 1, false, nil, engineNone},
		{"script", engine(func(r *Report) { r.Format = "script" }), 3, false, nil, engineNone},
		{"unsigned standalone", engine(func(r *Report) { r.Signature = Signature{} }), 3, false, nil, engineNone},
		{"ad-hoc", engine(func(r *Report) { r.Signature.AdHoc = true }), 3, false, nil, engineNone},
		{"signature fails", engine(func(r *Report) { r.Signature.Verified = &no }), 3, false, nil, engineNone},
		{"unverified standalone", engine(func(r *Report) { r.Signature.Verified = nil }), 3, false, nil, engineNone},
		{"sealed bundle: pending, not trusted", engine(func(r *Report) { r.Signature.Verified = nil }), 3, true, nil, enginePending},
		{"sealed bundle, few exports", engine(func(r *Report) { r.Signature.Verified = nil; r.Slices[0].ExportCount = 3 }), 3, true, nil, engineNone},
		{"sealed bundle, no team", engine(func(r *Report) { r.Signature.Verified = nil; r.Signature.TeamID = "" }), 3, true, nil, engineNone},
		{"sealed bundle, unsigned", engine(func(r *Report) { r.Signature = Signature{} }), 3, true, nil, engineNone},
		{"wallets", engine(nil), 3, false, []Finding{{ID: "stealer-wallets", Severity: High}}, engineNone},
		{"webhook", engine(nil), 3, false, []Finding{{ID: "exfil-webhooks", Severity: Medium}}, engineNone},
		{"keychain escalated", engine(nil), 3, false, []Finding{{ID: "keychain-theft", Severity: High}}, engineNone},
		{"keychain single", engine(nil), 3, false, []Finding{{ID: "keychain-theft", Severity: Low}}, engineTrusted},
		{"sealed bundle, verified signer", engine(nil), 3, true, nil, engineTrusted},
		{"sealed bundle, signature fails", engine(func(r *Report) { r.Signature.Verified = &no }), 3, true, nil, engineNone},
		{"sealed bundle, ad-hoc", engine(func(r *Report) { r.Signature.Verified = nil; r.Signature.AdHoc = true }), 3, true, nil, engineNone},
		{"sealed bundle, wallets", engine(func(r *Report) { r.Signature.Verified = nil }), 3, true, []Finding{{ID: "stealer-wallets", Severity: High}}, engineNone},
	}
	for _, c := range cases {
		if got := browserEngine(c.r, c.markers, c.sealed, c.fs); got != c.want {
			t.Errorf("%s: browserEngine = %v, want %v", c.name, got, c.want)
		}
	}
}

// A pending engine report keeps its findings until a container confirms
// the enclosing seal; confirmation demotes only the inherent findings and
// rescores, and is a no-op for reports that are not pending.
func TestConfirmBrowserEngine(t *testing.T) {
	eng := newTestEngine(t, time.Second)
	mk := func(pending bool) *Report {
		r := &Report{Format: "Mach-O", EnginePending: pending, Findings: []Finding{
			{ID: "stealer-cred-files", Severity: High},
			{ID: "api-keylogging", Severity: Medium},
			{ID: "api-priv-exec-mac", Severity: Medium},
			{ID: "ioc-ip-url", Severity: Medium},
		}}
		eng.Finalize(r)
		return r
	}
	r := mk(true)
	before := r.Score
	if findingIDs(r)["stealer-cred-files"] != High {
		t.Fatalf("pending report already demoted: %+v", r.Findings)
	}
	eng.ConfirmBrowserEngine(r)
	got := findingIDs(r)
	for _, id := range []string{"stealer-cred-files", "api-keylogging", "api-priv-exec-mac"} {
		if got[id] != Info {
			t.Errorf("confirmed: %s = %v, want info", id, got[id])
		}
	}
	if got["ioc-ip-url"] != Medium || r.EnginePending || r.Score >= before {
		t.Errorf("confirmed: ioc %v pending %v score %d (was %d)", got["ioc-ip-url"], r.EnginePending, r.Score, before)
	}
	r = mk(false)
	eng.ConfirmBrowserEngine(r)
	if findingIDs(r)["stealer-cred-files"] != High {
		t.Error("ConfirmBrowserEngine demoted a report that was not pending")
	}
}

// A file loose in a disk image or package has its signature parsed but
// never checked (the signer and team ID are forgeable), so only a file in a
// sealed app bundle may borrow the engine exemption, and only once the
// container has confirmed the seal. TestBrowserEngineGate and
// TestConfirmBrowserEngine cover the same logic hermetically. Uses a real Electron
// framework when one is installed: its genuine signature stands in for a
// transplanted one.
func TestLooseEngineInContainerNotDemoted(t *testing.T) {
	if testing.Short() {
		t.Skip("reads a large framework")
	}
	m, _ := filepath.Glob("/Applications/*.app/Contents/Frameworks/Electron Framework.framework/Electron Framework")
	if len(m) == 0 {
		t.Skip("no Electron app installed")
	}
	eng := newTestEngine(t, time.Minute)
	inherent := func(r *Report) map[string]Severity {
		got := map[string]Severity{}
		for id, sev := range findingIDs(r) {
			switch id {
			case "stealer-cred-files", "api-keylogging", "api-priv-exec-mac":
				got[id] = sev
			}
		}
		if len(got) == 0 {
			t.Skipf("%s has none of the demotable findings", m[0])
		}
		return got
	}
	loose := inherent(eng.Analyze(context.Background(), m[0], Meta{SkipVerify: true}))
	for id, sev := range loose {
		if sev == Info {
			t.Errorf("loose in container: %s demoted to info", id)
		}
	}
	// In an app bundle the parsed signature earns nothing on its own: the
	// report is only marked pending until the container confirms the seal.
	r := eng.Analyze(context.Background(), m[0], Meta{SkipVerify: true, Sealed: true})
	if !r.EnginePending {
		t.Errorf("in sealed bundle: not marked pending")
	}
	for id, sev := range inherent(r) {
		if sev == Info {
			t.Errorf("in sealed bundle, unconfirmed: %s demoted to info", id)
		}
	}
	eng.ConfirmBrowserEngine(r)
	for id, sev := range inherent(r) {
		if sev != Info {
			t.Errorf("in sealed bundle, confirmed: %s = %v, want info", id, sev)
		}
	}
}
