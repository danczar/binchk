package provenance

import (
	"bufio"
	"os"
	"strings"

	"github.com/danczar/binchk/internal/analyze"
)

var zones = map[string]string{"0": "Local machine", "1": "Local intranet", "2": "Trusted sites", "3": "Internet", "4": "Restricted sites"}

// read parses the Mark-of-the-Web alternate data stream.
func read(path string) analyze.Provenance {
	var p analyze.Provenance
	f, err := os.Open(path + ":Zone.Identifier")
	if err != nil {
		return p
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch k {
		case "ZoneId":
			p.Zone = zones[v]
			if p.Zone == "" {
				p.Zone = "zone " + v
			}
		case "HostUrl":
			p.Source = v
		case "ReferrerUrl":
			p.Referrer = v
		}
	}
	return p
}
