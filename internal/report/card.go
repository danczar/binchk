package report

import (
	_ "embed"
	"html/template"
	"io"
	"strings"
	"time"
)

//go:embed card.html.tmpl
var cardSrc string

var cardTmpl = template.Must(template.New("card").Funcs(template.FuncMap{
	"bytes": humanBytes,
	"join":  strings.Join,
	"time":  func(t time.Time) string { return t.Local().Format("2006-01-02 15:04 MST") },
}).Parse(cardSrc))

// CardFinding is one line of a card's findings list.
type CardFinding struct {
	Severity string // info, low, medium, high, critical
	Title    string
}

// CardData is everything the compact card shows. All of it is escaped.
type CardData struct {
	FileName   string
	Path       string
	Format     string
	Arches     []string
	Size       int64
	Verdict    string
	Score      int
	Summary    string
	Signer     string
	Notarized  bool
	Gatekeeper string
	Findings   []CardFinding
	AnalyzedAt time.Time
	MarkedSafe bool
	Version    string
}

// WriteCard renders the compact, self-contained card shown by Quick Look:
// inline CSS only, no scripts, no external resources.
func WriteCard(w io.Writer, c *CardData) error {
	return cardTmpl.Execute(w, c)
}
