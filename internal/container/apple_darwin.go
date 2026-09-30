package container

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
)

const supportsDMG = true

// These wrap Apple's own trust tools. Notarization, revocation and the
// bundle seal are Apple's verdicts to give; binchk reports them.

// bundleVerify checks the whole bundle's seal (every file, nested code).
func bundleVerify(ctx context.Context, p string) (ok, unsigned bool, detail string, err error) {
	out, err := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--deep", "--verbose=1", p).CombinedOutput()
	if ctx.Err() != nil {
		return false, false, "", ctx.Err()
	}
	msg := strings.TrimSpace(strings.ReplaceAll(string(out), p+": ", ""))
	msg = strings.ReplaceAll(msg, "\n", "; ")
	if err == nil {
		return true, false, msg, nil
	}
	return false, strings.Contains(msg, "not signed at all"), msg, nil
}

// codesignInfo returns codesign -dvv's Key=Value lines (Authority repeats).
func codesignInfo(ctx context.Context, p string) (map[string][]string, error) {
	out, err := exec.CommandContext(ctx, "/usr/bin/codesign", "-dvv", p).CombinedOutput()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	m := map[string][]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && !strings.Contains(k, " ") {
			m[k] = append(m[k], v)
		} else if strings.HasPrefix(line, "CodeDirectory") {
			if i := strings.Index(line, "flags="); i >= 0 {
				f := line[i+6:]
				if j := strings.IndexByte(f, ' '); j >= 0 {
					f = f[:j]
				}
				m["flags"] = []string{f}
			}
		}
	}
	if len(m) == 0 && err != nil {
		return nil, err
	}
	return m, nil
}

type gkResult struct {
	accepted bool
	source   string
	origin   string
	raw      string
}

// gatekeeper runs spctl: the same assessment macOS makes when the user
// opens the app (typ "execute") or installer (typ "install").
func gatekeeper(ctx context.Context, p, typ string) (gkResult, error) {
	out, err := exec.CommandContext(ctx, "/usr/sbin/spctl", "--assess", "--type", typ, "-vv", p).CombinedOutput()
	if ctx.Err() != nil {
		return gkResult{}, ctx.Err()
	}
	var g gkResult
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch {
		case strings.HasPrefix(line, "source="):
			g.source = strings.TrimPrefix(line, "source=")
		case strings.HasPrefix(line, "origin="):
			g.origin = strings.TrimPrefix(line, "origin=")
		case strings.HasSuffix(line, ": accepted"):
			g.accepted = true
		case strings.HasPrefix(line, p+": "):
			g.raw = strings.TrimPrefix(line, p+": ")
		}
	}
	if !g.accepted && g.raw == "" && err != nil && !strings.Contains(string(out), "rejected") {
		return g, errors.New(strings.TrimSpace(string(out)))
	}
	return g, nil
}

type pkgSig struct {
	status, notarization string
	chain                []string
}

func pkgSignature(ctx context.Context, p string) (pkgSig, error) {
	out, _ := exec.CommandContext(ctx, "/usr/sbin/pkgutil", "--check-signature", p).CombinedOutput()
	if ctx.Err() != nil {
		return pkgSig{}, ctx.Err()
	}
	var s pkgSig
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "Status: "):
			s.status = strings.TrimPrefix(t, "Status: ")
		case strings.HasPrefix(t, "Notarization: "):
			s.notarization = strings.TrimPrefix(t, "Notarization: ")
		case len(t) > 3 && t[0] >= '1' && t[0] <= '9' && strings.Contains(t[:3], ". "):
			_, name, _ := strings.Cut(t, ". ")
			s.chain = append(s.chain, name)
		}
	}
	if s.status == "" {
		return s, errors.New(strings.TrimSpace(string(out)))
	}
	return s, nil
}

// readPlist returns top-level scalar values of a plist (XML or binary).
func readPlist(ctx context.Context, p string) (map[string]string, error) {
	out, err := exec.CommandContext(ctx, "/usr/bin/plutil", "-convert", "json", "-o", "-", p).Output()
	if err != nil {
		return readXMLPlist(p)
	}
	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}
	m := map[string]string{}
	for k, v := range raw {
		switch x := v.(type) {
		case string:
			m[k] = x
		case bool:
			m[k] = map[bool]string{true: "true", false: "false"}[x]
		case float64:
			m[k] = jsonNum(x)
		}
	}
	return m, nil
}
