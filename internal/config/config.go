// Package config loads binchk's JSON configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Duration marshals as a Go duration string ("10s").
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

type WatchDir struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
}

type Config struct {
	WatchDirs []WatchDir `json:"watch_dirs"`
	// AnalysisBudget is the hard deadline for one analysis. The whole
	// pipeline (settle -> analyse -> report) targets < 15s.
	AnalysisBudget Duration `json:"analysis_budget"`
	// SettleDelay: a file must be unchanged this long before it is scanned,
	// so half-written downloads are not analysed.
	SettleDelay     Duration `json:"settle_delay"`
	MaxFileSize     int64    `json:"max_file_size"`
	ConcurrentScans int      `json:"concurrent_scans"`
	// Notifications enables desktop notifications for the verdicts listed
	// in NotifyVerdicts.
	Notifications  bool     `json:"notifications"`
	NotifyVerdicts []string `json:"notify_verdicts"`
	// FinderTags (macOS) tags analysed files whose verdict is listed in
	// TagVerdicts ("binchk: Suspicious", orange). Other verdicts, and files
	// marked safe, have binchk's tag removed.
	FinderTags       bool     `json:"finder_tags"`
	TagVerdicts      []string `json:"tag_verdicts"`
	VerifySignatures bool     `json:"verify_signatures"`
	// InspectInstallers: on macOS, also inspect app bundles, disk images
	// (.dmg) and installer packages (.pkg).
	InspectInstallers bool     `json:"inspect_installers"`
	IgnoreExtensions  []string `json:"ignore_extensions"`
	// Optional paths; relative paths resolve against the config directory.
	RulesFile     string `json:"rules_file,omitempty"`
	BlocklistFile string `json:"blocklist_file,omitempty"`
	AllowlistFile string `json:"allowlist_file,omitempty"`
	DataDir       string `json:"data_dir,omitempty"`

	path string
}

func Default() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		WatchDirs:         []WatchDir{{Path: filepath.Join(home, "Downloads"), Recursive: false}},
		AnalysisBudget:    Duration(10 * time.Second),
		SettleDelay:       Duration(400 * time.Millisecond),
		MaxFileSize:       4 << 30,
		ConcurrentScans:   2,
		Notifications:     true,
		NotifyVerdicts:    []string{"Suspicious", "Malicious"},
		FinderTags:        true,
		TagVerdicts:       []string{"Suspicious", "Malicious"},
		VerifySignatures:  true,
		InspectInstallers: true,
		IgnoreExtensions:  []string{".crdownload", ".part", ".partial", ".download", ".tmp", ".opdownload", ".!ut"},
		RulesFile:         "rules.json",
		BlocklistFile:     "blocklist.txt",
		AllowlistFile:     "allowlist.txt",
	}
}

// Dir is the per-user configuration directory.
func Dir() string {
	d, err := os.UserConfigDir()
	if err != nil {
		d = os.TempDir()
	}
	return filepath.Join(d, "binchk")
}

// DefaultPath is where Load looks when no path is given.
func DefaultPath() string { return filepath.Join(Dir(), "config.json") }

// Load reads path (or DefaultPath), writing a default file on first run.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}
	c := Default()
	c.path = path
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := c.Save(); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	for i := range c.WatchDirs {
		c.WatchDirs[i].Path = expandHome(c.WatchDirs[i].Path)
	}
	if c.ConcurrentScans < 1 {
		c.ConcurrentScans = 1
	}
	return c, nil
}

func (c *Config) Save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, append(b, '\n'), 0o600)
}

func (c *Config) Path() string { return c.path }

// Notifies reports whether a verdict gets a notification.
func (c *Config) Notifies(verdict string) bool {
	return c.Notifications && containsFold(c.NotifyVerdicts, verdict)
}

// Tags reports whether a verdict gets a Finder tag.
func (c *Config) Tags(verdict string) bool {
	return c.FinderTags && containsFold(c.TagVerdicts, verdict)
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(strings.TrimSpace(v), s) {
			return true
		}
	}
	return false
}

// Resolve makes an optional config-relative path absolute ("" stays "").
func (c *Config) Resolve(p string) string {
	if p == "" {
		return ""
	}
	p = expandHome(p)
	if !filepath.IsAbs(p) {
		p = filepath.Join(filepath.Dir(c.path), p)
	}
	return p
}

// DataPath is where reports, the report index and state live.
func (c *Config) DataPath() string {
	if c.DataDir != "" {
		return c.Resolve(c.DataDir)
	}
	if runtime.GOOS == "linux" {
		if x := os.Getenv("XDG_DATA_HOME"); x != "" {
			return filepath.Join(x, "binchk")
		}
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".local", "share", "binchk")
	}
	if runtime.GOOS == "windows" {
		if l := os.Getenv("LOCALAPPDATA"); l != "" {
			return filepath.Join(l, "binchk")
		}
	}
	return Dir()
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[1:])
	}
	return os.ExpandEnv(p)
}
