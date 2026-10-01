package analyze

import (
	"debug/buildinfo"
	"strings"
)

// Go modules associated with offensive tooling. Matching one is a strong
// signal: legitimate software has no reason to link a C2 implant framework.
var offensiveGoModules = []string{
	"github.com/BishopFox/sliver", "github.com/Ne0nd0g/merlin", "github.com/C-Sto/BananaPhone", "github.com/Binject/",
	"github.com/D00MFist/", "github.com/moloch--/", "github.com/b1naryth1ef/", "github.com/HavocFramework/",
	"github.com/praetorian-inc/goffloader", "github.com/Ne0nd0g/go-clr", "github.com/timwhitez/", "github.com/optiv/ScareCrow",
	"github.com/kbinani/screenshot", "github.com/MarinX/keylogger", "github.com/moutend/go-hook",
}

// goToolchain reads Go's embedded build info, which names every module the
// binary was built from.
func goToolchain(data []byte) (*Toolchain, []Finding) {
	bi, err := buildinfo.Read(parserReader(data))
	if err != nil {
		return nil, nil
	}
	tc := &Toolchain{Language: "Go", Version: bi.GoVersion, Module: bi.Path}
	var bad []string
	for _, d := range bi.Deps {
		tc.Deps = append(tc.Deps, d.Path+" "+d.Version)
		for _, m := range offensiveGoModules {
			if strings.HasPrefix(d.Path, m) {
				bad = append(bad, d.Path)
			}
		}
	}
	for _, s := range bi.Settings {
		if s.Key == "-ldflags" && strings.Contains(s.Value, "-H=windowsgui") {
			tc.Notes = append(tc.Notes, "built as a windowless GUI program")
		}
	}
	var fs []Finding
	if len(bad) > 0 {
		sev := High
		for _, b := range bad {
			if strings.Contains(b, "screenshot") || strings.Contains(b, "keylogger") || strings.Contains(b, "go-hook") {
				sev = Medium
			} else {
				sev = High
				break
			}
		}
		fs = append(fs, Finding{ID: "go-offensive-deps", Title: "Built with offensive-security Go modules", Severity: sev, Category: "toolchain", Evidence: bad})
	}
	return tc, fs
}
