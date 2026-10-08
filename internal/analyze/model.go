package analyze

import (
	"encoding/json"
	"time"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var sevNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(sevNames) {
		return "unknown"
	}
	return sevNames[s]
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	*s = ParseSeverity(str)
	return nil
}

func ParseSeverity(s string) Severity {
	for i, n := range sevNames {
		if n == s {
			return Severity(i)
		}
	}
	return Medium
}

// weight is the score contribution of a single finding.
func (s Severity) weight() int {
	return [...]int{0, 4, 12, 30, 60}[s]
}

type Verdict string

const (
	VerdictClean      Verdict = "Clean"
	VerdictSuspicious Verdict = "Suspicious"
	VerdictMalicious  Verdict = "Malicious"
	VerdictError      Verdict = "Error"
)

type Finding struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"`
	Severity Severity `json:"severity"`
	Category string   `json:"category"`
	Evidence []string `json:"evidence,omitempty"`
}

type Hashes struct {
	MD5     string `json:"md5,omitempty"`
	SHA1    string `json:"sha1,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Imphash string `json:"imphash,omitempty"`
}

type Section struct {
	Name    string  `json:"name"`
	Offset  uint64  `json:"offset"`
	Size    uint64  `json:"size"`
	Addr    uint64  `json:"addr"`
	Perms   string  `json:"perms"` // "rwx" style
	Entropy float64 `json:"entropy"`
}

type Import struct {
	Lib  string `json:"lib,omitempty"`
	Name string `json:"name"`
	// Category is set when the API is on binchk's list of notable APIs.
	Category string `json:"category,omitempty"`
}

type Signature struct {
	Present    bool     `json:"present"`
	Kind       string   `json:"kind,omitempty"` // Authenticode, Apple code signature
	AdHoc      bool     `json:"adhoc,omitempty"`
	Signer     string   `json:"signer,omitempty"`
	Issuer     string   `json:"issuer,omitempty"`
	TeamID     string   `json:"team_id,omitempty"`
	Identifier string   `json:"identifier,omitempty"`
	NotAfter   string   `json:"not_after,omitempty"`
	Hardened   bool     `json:"hardened_runtime,omitempty"`
	Platform   bool     `json:"platform,omitempty"` // Apple OS component
	Flags      []string `json:"flags,omitempty"`
	// Gatekeeper is spctl's assessment ("accepted: Notarized Developer ID").
	Gatekeeper string `json:"gatekeeper,omitempty"`
	Notarized  bool   `json:"notarized,omitempty"`
	// Verified is nil when no OS-level verification was possible.
	Verified     *bool  `json:"verified,omitempty"`
	VerifyDetail string `json:"verify_detail,omitempty"`
}

// Slice is one architecture inside a binary (universal Mach-O has several).
type Slice struct {
	Arch        string            `json:"arch"`
	Kind        string            `json:"kind"` // executable, shared library, ...
	Bits        int               `json:"bits"`
	Entry       uint64            `json:"entry,omitempty"`
	EntrySect   string            `json:"entry_section,omitempty"`
	Sections    []Section         `json:"sections,omitempty"`
	Segments    []Section         `json:"segments,omitempty"`
	Libraries   []string          `json:"libraries,omitempty"`
	Imports     []Import          `json:"imports,omitempty"`
	ExportCount int               `json:"export_count,omitempty"`
	Props       map[string]string `json:"props,omitempty"`
}

type Toolchain struct {
	Language string   `json:"language,omitempty"`
	Version  string   `json:"version,omitempty"`
	Module   string   `json:"module,omitempty"`
	Deps     []string `json:"deps,omitempty"`
	Notes    []string `json:"notes,omitempty"`
}

type Strings struct {
	Total  int      `json:"total"`
	URLs   []string `json:"urls,omitempty"`
	IPs    []string `json:"ips,omitempty"`
	Onions []string `json:"onions,omitempty"`
	Crypto []string `json:"crypto,omitempty"`
}

type RuleHit struct {
	Rule     string   `json:"rule"`
	Matches  []string `json:"matches"`
	Severity Severity `json:"severity"`
}

type Provenance struct {
	Source   string `json:"source,omitempty"`   // URL the file came from
	Referrer string `json:"referrer,omitempty"` // page that linked it
	Agent    string `json:"agent,omitempty"`    // app that downloaded it
	Zone     string `json:"zone,omitempty"`     // Windows security zone
}

type Timing struct {
	Name     string        `json:"name"`
	Duration time.Duration `json:"duration"`
	Status   string        `json:"status"` // ok, timeout, error
	Error    string        `json:"error,omitempty"`
}

// Report is the complete result of analysing one file.
type Report struct {
	ID           string     `json:"id"`
	FileName     string     `json:"file_name"`
	OriginalPath string     `json:"original_path"`
	Size         int64      `json:"size"`
	Format       string     `json:"format"`
	Arches       []string   `json:"arches,omitempty"`
	Hashes       Hashes     `json:"hashes"`
	Entropy      float64    `json:"entropy"`
	EntropyMap   []float64  `json:"entropy_map,omitempty"`
	EntropyBlock int        `json:"entropy_block,omitempty"`
	Slices       []Slice    `json:"slices,omitempty"`
	Signature    Signature  `json:"signature"`
	Toolchain    Toolchain  `json:"toolchain"`
	Strings      Strings    `json:"strings"`
	RuleHits     []RuleHit  `json:"rule_hits,omitempty"`
	Overlay      int64      `json:"overlay,omitempty"`
	Provenance   Provenance `json:"provenance"`
	Container    *Container `json:"container,omitempty"`
	Findings     []Finding  `json:"findings"`
	Score        int        `json:"score"`
	Verdict      Verdict    `json:"verdict"`
	Summary      string     `json:"summary"`
	Timings      []Timing   `json:"timings"`
	Truncated    bool       `json:"truncated,omitempty"`
	DetectedAt   time.Time  `json:"detected_at"`
	AnalyzedAt   time.Time  `json:"analyzed_at"`
	// Elapsed is analysis wall time; Latency is detection -> report ready.
	Elapsed time.Duration `json:"elapsed"`
	Latency time.Duration `json:"latency,omitempty"`
	// EnginePending: a browser engine whose demotion awaits the enclosing
	// bundle's seal verification (see Meta.Sealed). Never persisted.
	EnginePending bool `json:"-"`
}

// KV is an ordered key/value pair for display.
type KV struct {
	K string `json:"k"`
	V string `json:"v"`
}

// Container describes what was found inside a disk image or installer.
type Container struct {
	Kind    string          `json:"kind"`
	Volume  string          `json:"volume,omitempty"`
	Notes   []string        `json:"notes,omitempty"`
	Bundles []Bundle        `json:"bundles,omitempty"`
	Files   []ContainedFile `json:"files,omitempty"`
	Skipped int             `json:"skipped,omitempty"` // files over the analysis cap
}

// Bundle is an app or installer package found inside a container.
type Bundle struct {
	Path  string `json:"path"`
	Kind  string `json:"kind"`
	Props []KV   `json:"props,omitempty"`
}

// ContainedFile is the condensed analysis of one file inside a container.
type ContainedFile struct {
	Path      string        `json:"path"`
	Kind      string        `json:"kind"`
	Format    string        `json:"format"`
	Arches    []string      `json:"arches,omitempty"`
	Size      int64         `json:"size"`
	SHA256    string        `json:"sha256,omitempty"`
	Verdict   Verdict       `json:"verdict"`
	Score     int           `json:"score"`
	Summary   string        `json:"summary"`
	Signer    string        `json:"signer,omitempty"`
	Findings  []Finding     `json:"findings,omitempty"`
	Elapsed   time.Duration `json:"elapsed"`
	Truncated bool          `json:"truncated,omitempty"`
}

// Meta is caller-provided context about the file being analysed.
type Meta struct {
	ID           string
	FileName     string
	OriginalPath string
	Provenance   Provenance
	DetectedAt   time.Time
	// SkipVerify disables per-file OS signature verification (containers
	// verify whole bundles instead).
	SkipVerify bool
	// Sealed: with SkipVerify, the file is inside an app bundle whose seal
	// the container checks (codesign --deep). Its parsed signature still
	// earns nothing by itself: the engine only marks the report
	// EnginePending, and the container calls ConfirmBrowserEngine once the
	// seal has verified. Loose files in a container are never pending.
	Sealed bool
}
