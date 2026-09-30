// Package report renders analysis results as a self-contained HTML page.
package report

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/danczar/binchk/internal/analyze"
)

//go:embed report.html.tmpl
var tmplSrc string

var tmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"bytes":     humanBytes,
	"bytesi":    func(n int) string { return humanBytes(int64(n)) },
	"bytes64":   func(n uint64) string { return humanBytes(int64(n)) },
	"ms":        func(d time.Duration) string { return fmt.Sprintf("%.1f ms", float64(d.Microseconds())/1000) },
	"hex":       func(v uint64) string { return fmt.Sprintf("0x%x", v) },
	"f2":        func(v float64) string { return fmt.Sprintf("%.2f", v) },
	"pct":       func(v float64) string { return fmt.Sprintf("%.1f", v/8*100) },
	"sev":       func(s analyze.Severity) string { return s.String() },
	"lower":     strings.ToLower,
	"time":      func(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05 MST") },
	"entropy":   entropySVG,
	"notable":   notable,
	"verified":  func(p *bool) string { return map[bool]string{true: "yes", false: "no"}[p != nil && *p] },
	"hasVerify": func(p *bool) bool { return p != nil },
	"join":      strings.Join,
	"entClass": func(e float64) string {
		switch {
		case e >= 7.2:
			return "hot"
		case e >= 6.5:
			return "warm"
		}
		return ""
	},
}).Parse(tmplSrc))

// Write renders r to path atomically.
func Write(r *analyze.Report, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := tmpl.Execute(f, r); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// WriteJSON stores the raw report next to the HTML for tooling.
func WriteJSON(r *analyze.Report, path string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// notable returns only the imports binchk flagged, for the summary table.
func notable(imps []analyze.Import) []analyze.Import {
	var out []analyze.Import
	for _, im := range imps {
		if im.Category != "" {
			out = append(out, im)
		}
	}
	return out
}

// entropySVG draws the per-block entropy map as an area chart.
func entropySVG(blocks []float64) template.HTML {
	if len(blocks) == 0 {
		return ""
	}
	const w, h = 800.0, 120.0
	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %g %g" preserveAspectRatio="none" class="entropy" role="img" aria-label="Entropy by file offset">`, w, h)
	// reference line at 7.2 bits (packed threshold)
	y72 := h - 7.2/8*h
	fmt.Fprintf(&b, `<line x1="0" x2="%g" y1="%.1f" y2="%.1f" class="thresh"/>`, w, y72, y72)
	var pts strings.Builder
	n := len(blocks)
	step := w / math.Max(float64(n-1), 1)
	fmt.Fprintf(&pts, "0,%g ", h)
	for i, e := range blocks {
		fmt.Fprintf(&pts, "%.1f,%.1f ", float64(i)*step, h-e/8*h)
	}
	if n == 1 {
		fmt.Fprintf(&pts, "%g,%.1f ", w, h-blocks[0]/8*h)
	}
	fmt.Fprintf(&pts, "%g,%g", w, h)
	fmt.Fprintf(&b, `<polygon points="%s" class="area"/>`, pts.String())
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}
