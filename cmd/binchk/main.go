// Command binchk watches folders for new executables, analyses them where
// they are in seconds, and reports through the system tray, Finder tags and
// the report index the Quick Look extension reads.
//
//	binchk                 run the tray app (default)
//	binchk watch           run headless, logging to stdout
//	binchk scan FILE...    analyse files, write reports and index them
package main

import (
	"context"
	"flag"
	"fmt"
	iofs "io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/danczar/binchk/internal/analyze"
	"github.com/danczar/binchk/internal/app"
	"github.com/danczar/binchk/internal/config"
	"github.com/danczar/binchk/internal/container"
	"github.com/danczar/binchk/internal/detect"
	"github.com/danczar/binchk/internal/index"
	"github.com/danczar/binchk/internal/opener"
	"github.com/danczar/binchk/internal/provenance"
	"github.com/danczar/binchk/internal/report"
	"github.com/danczar/binchk/internal/tray"
)

var version = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, `binchk %s — fast triage of new executables

usage:
  binchk [-config FILE]                 run in the system tray
  binchk watch [-config FILE]           watch folders headless (logs to stdout)
  binchk scan [-open] [-json] [-no-index] [-out DIR] FILE|APP|DIR...
                                        analyse files and write reports; directories
                                        are searched. Results are added to the report
                                        index and Finder tags unless -no-index
  binchk version

config: %s
`, version, config.DefaultPath())
}

func main() {
	attachConsole()
	args := os.Args[1:]
	cmd := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "", "tray":
		fs := flag.NewFlagSet("tray", flag.ExitOnError)
		cfgPath := fs.String("config", "", "config file")
		fs.Parse(args)
		a := mustApp(*cfgPath, true)
		tray.Run(a)
	case "watch":
		fs := flag.NewFlagSet("watch", flag.ExitOnError)
		cfgPath := fs.String("config", "", "config file")
		fs.Parse(args)
		a := mustApp(*cfgPath, false)
		if err := a.Start(); err != nil {
			fatal(err)
		}
		select {}
	case "scan":
		os.Exit(scan(args))
	case "version":
		fmt.Println("binchk", version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func mustApp(cfgPath string, logToFile bool) *app.App {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fatal(err)
	}
	a, err := app.New(cfg, logToFile, version)
	if err != nil {
		fatal(err)
	}
	return a
}

func scan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	cfgPath := fs.String("config", "", "config file (for rules and hash lists)")
	out := fs.String("out", "", "directory for reports (default: next to the config's data dir)")
	open := fs.Bool("open", false, "open each HTML report")
	asJSON := fs.Bool("json", false, "also write a .json report")
	budget := fs.Duration("budget", 0, "override the analysis time budget")
	noIndex := fs.Bool("no-index", false, "do not add results to the report index or set Finder tags")
	fs.Parse(args)
	if fs.NArg() == 0 {
		usage()
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal(err)
	}
	if *budget > 0 {
		cfg.AnalysisBudget = config.Duration(*budget)
	}
	eng, allow, err := app.NewEngineAllow(cfg)
	if err != nil {
		fatal(err)
	}
	dir := *out
	if dir == "" {
		dir = filepath.Join(cfg.DataPath(), "reports")
	}
	if dir, err = filepath.Abs(dir); err != nil {
		fatal(err)
	}
	rec := &app.Recorder{Config: cfg, Allow: allow, Version: version, NoTags: *noIndex}
	if !*noIndex {
		if rec.Index, err = index.Open(cfg.DataPath()); err != nil {
			fatal(err)
		}
	}
	// Expand directories to the executables inside them.
	var files []string
	for _, arg := range fs.Args() {
		st, err := os.Stat(arg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if !st.IsDir() || detect.IsAppBundle(arg) {
			files = append(files, arg)
			continue
		}
		filepath.WalkDir(arg, func(p string, d iofs.DirEntry, err error) error {
			switch {
			case err != nil:
			case d.IsDir() && detect.IsAppBundle(p):
				files = append(files, p) // an app is analysed as one unit
				return filepath.SkipDir
			case d.Type().IsRegular() && detect.SniffFile(p) != detect.Unknown:
				files = append(files, p)
			}
			return nil
		})
	}
	worst := 0
	for _, path := range files {
		abs, _ := filepath.Abs(path)
		idSt, idErr := app.IdentityStat(abs)
		if idErr != nil {
			idSt = nil
		}
		t0 := time.Now()
		r := container.Analyze(context.Background(), eng, abs, analyze.Meta{
			ID:         fmt.Sprintf("scan-%s-%s", time.Now().Format("20060102-150405"), sanitize(filepath.Base(abs))),
			Provenance: provenance.Read(abs), DetectedAt: t0,
		})
		html := filepath.Join(dir, r.ID+".html")
		if err := report.Write(r, html); err != nil {
			fmt.Fprintln(os.Stderr, "report:", err)
		}
		if *asJSON {
			_ = report.WriteJSON(r, strings.TrimSuffix(html, ".html")+".json")
		}
		if _, err := rec.Record(r, abs, html, idSt); err != nil {
			fmt.Fprintln(os.Stderr, "index:", err)
		}
		fmt.Printf("%-11s %3d  %-8s %8.1f ms  %s\n", r.Verdict, r.Score, r.Format, float64(r.Elapsed.Microseconds())/1000, path)
		fmt.Printf("            %s\n            report: %s\n", r.Summary, html)
		if *open {
			opener.Open(html)
		}
		switch r.Verdict {
		case analyze.VerdictMalicious:
			worst = max(worst, 3)
		case analyze.VerdictSuspicious:
			worst = max(worst, 2)
		case analyze.VerdictError:
			worst = max(worst, 1)
		}
	}
	return worst
}

func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || strings.ContainsRune(`/\:*?"<>|`, r) || r > 0x7e {
			return '_'
		}
		return r
	}, s)
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "binchk:", err)
	os.Exit(1)
}
