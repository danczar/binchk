package analyze

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode/utf16"

	"github.com/danczar/binchk/internal/ac"
)

// Rule is a content signature. A rule fires when at least Min distinct
// patterns (strings or hex) occur anywhere in the file. Text patterns are
// matched case-insensitively (unless CaseSensitive) in both ASCII/UTF-8 and
// UTF-16LE encodings.
type Rule struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Description   string   `json:"description,omitempty"`
	Category      string   `json:"category"`
	Severity      Severity `json:"severity"`
	Strings       []string `json:"strings,omitempty"`
	Hex           []string `json:"hex,omitempty"`
	CaseSensitive bool     `json:"case_sensitive,omitempty"`
	Min           int      `json:"min,omitempty"`
	// When EscalateAt distinct patterns match, severity becomes EscalateTo.
	EscalateAt int      `json:"escalate_at,omitempty"`
	EscalateTo Severity `json:"escalate_to,omitempty"`
}

// CategoryToolchain rules describe how a binary was built; they feed the
// report's toolchain section instead of producing findings.
const CategoryToolchain = "toolchain"

// The built-in rules live in rules/builtin.json (the file to edit) and are
// embedded gzip-compressed. Compression keeps every signature string out of
// binchk's own binary — otherwise binchk would flag itself as malware, as
// would any scanner that sees it. Run `go generate ./...` after editing.
//
//go:generate go run gen_rules.go
//go:embed rules/builtin.json.gz
var builtinRulesGz []byte

var builtinRules = func() []Rule {
	zr, err := gzip.NewReader(bytes.NewReader(builtinRulesGz))
	if err != nil {
		panic(err)
	}
	var rules []Rule
	if err := json.NewDecoder(zr).Decode(&rules); err != nil {
		panic("builtin rules: " + err.Error())
	}
	return rules
}()

// ruleSet is the compiled form of all rules.
type ruleSet struct {
	rules   []Rule
	m       *ac.Matcher
	pidRule []int32    // pattern id -> rule index
	pidLog  []int32    // pattern id -> logical pattern index within rule
	logText [][]string // rule -> logical pattern display text
}

func compileRules(rules []Rule) (*ruleSet, error) {
	rs := &ruleSet{rules: rules, logText: make([][]string, len(rules))}
	var pats []ac.Pattern
	add := func(ri, li int, b []byte, nocase bool) {
		pats = append(pats, ac.Pattern{Bytes: b, NoCase: nocase})
		rs.pidRule = append(rs.pidRule, int32(ri))
		rs.pidLog = append(rs.pidLog, int32(li))
	}
	for ri, r := range rules {
		for _, s := range r.Strings {
			if len(s) < 3 {
				return nil, fmt.Errorf("rule %s: pattern %q too short", r.ID, s)
			}
			li := len(rs.logText[ri])
			rs.logText[ri] = append(rs.logText[ri], s)
			add(ri, li, []byte(s), !r.CaseSensitive)
			add(ri, li, utf16le(s), !r.CaseSensitive)
		}
		for _, h := range r.Hex {
			b, err := hex.DecodeString(strings.ReplaceAll(h, " ", ""))
			if err != nil || len(b) < 3 {
				return nil, fmt.Errorf("rule %s: bad hex pattern %q", r.ID, h)
			}
			li := len(rs.logText[ri])
			rs.logText[ri] = append(rs.logText[ri], "hex:"+h)
			add(ri, li, b, false)
		}
	}
	rs.m = ac.Build(pats)
	return rs, nil
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i] = byte(c)
		b[2*i+1] = byte(c >> 8)
	}
	return b
}

// LoadRules reads user rules from a JSON file (an array of Rule).
func LoadRules(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i := range rules {
		if rules[i].ID == "" {
			rules[i].ID = fmt.Sprintf("custom-%d", i+1)
		}
		if rules[i].Title == "" {
			rules[i].Title = rules[i].ID
		}
		if rules[i].Category == "" {
			rules[i].Category = "custom"
		}
	}
	return rules, nil
}
