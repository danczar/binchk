package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A v0.1.x config (with auto_restore_clean, without the new keys) still
// loads, and gets the new defaults.
func TestLoadOldConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(p, []byte(`{"watch_dirs":[{"path":"/tmp/x"}],"auto_restore_clean":true,"notifications":true}`), 0o600)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !c.FinderTags || !c.Tags("Suspicious") || !c.Tags("Malicious") || c.Tags("Clean") {
		t.Errorf("tag defaults: %v %v", c.FinderTags, c.TagVerdicts)
	}
	if !c.Notifies("Malicious") || !c.Notifies("suspicious") || c.Notifies("Clean") || c.Notifies("Error") {
		t.Errorf("notify defaults: %v", c.NotifyVerdicts)
	}
}

func TestPolicyOff(t *testing.T) {
	c := Default()
	c.Notifications, c.FinderTags = false, false
	if c.Notifies("Malicious") || c.Tags("Malicious") {
		t.Fatal("policy ignores the master switches")
	}
	c = Default()
	c.TagVerdicts = []string{"Clean"}
	if !c.Tags("Clean") || c.Tags("Malicious") {
		t.Fatal("tag_verdicts ignored")
	}
}

func TestFirstRunWritesNewKeys(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if _, err := Load(p); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	for _, k := range []string{`"finder_tags": true`, `"tag_verdicts"`, `"notify_verdicts"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("config lacks %s:\n%s", k, b)
		}
	}
	if strings.Contains(string(b), "auto_restore_clean") {
		t.Error("config still has auto_restore_clean")
	}
}
