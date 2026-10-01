package analyze

import (
	"context"
	"os"
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
			for _, meta := range []Meta{{}, {SkipVerify: true}} {
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
		name      string
		r         *Report
		markers   int
		container bool
		fs        []Finding
		want      bool
	}{
		{"verified signer", engine(nil), 3, false, nil, true},
		{"one marker", engine(nil), 1, false, nil, false},
		{"script", engine(func(r *Report) { r.Format = "script" }), 3, false, nil, false},
		{"unsigned standalone", engine(func(r *Report) { r.Signature = Signature{} }), 3, false, nil, false},
		{"ad-hoc", engine(func(r *Report) { r.Signature.AdHoc = true }), 3, false, nil, false},
		{"signature fails", engine(func(r *Report) { r.Signature.Verified = &no }), 3, false, nil, false},
		{"unverified standalone", engine(func(r *Report) { r.Signature.Verified = nil }), 3, false, nil, false},
		{"in container", engine(func(r *Report) { r.Signature.Verified = nil }), 3, true, nil, true},
		{"in container, few exports", engine(func(r *Report) { r.Signature.Verified = nil; r.Slices[0].ExportCount = 3 }), 3, true, nil, false},
		{"in container, no team", engine(func(r *Report) { r.Signature.Verified = nil; r.Signature.TeamID = "" }), 3, true, nil, false},
		{"in container, unsigned", engine(func(r *Report) { r.Signature = Signature{} }), 3, true, nil, false},
		{"wallets", engine(nil), 3, false, []Finding{{ID: "stealer-wallets", Severity: High}}, false},
		{"webhook", engine(nil), 3, false, []Finding{{ID: "exfil-webhooks", Severity: Medium}}, false},
		{"keychain escalated", engine(nil), 3, false, []Finding{{ID: "keychain-theft", Severity: High}}, false},
		{"keychain single", engine(nil), 3, false, []Finding{{ID: "keychain-theft", Severity: Low}}, true},
	}
	for _, c := range cases {
		if got := browserEngine(c.r, c.markers, c.container, c.fs); got != c.want {
			t.Errorf("%s: browserEngine = %v, want %v", c.name, got, c.want)
		}
	}
}
