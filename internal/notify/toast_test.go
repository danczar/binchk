package notify

import (
	"encoding/xml"
	"strings"
	"testing"
)

// hostileNames try to break out of a PowerShell string or the toast XML.
var hostileNames = []string{
	"Setup'+(Start-Process calc)+'.exe",
	"Setup\u2018+(Start-Process calc)+\u2018.exe",
	"Setup\u2019+(Start-Process calc)+\u2019.exe",
	"Setup\u201A+(Start-Process calc)+\u201A.exe",
	"Setup\u201B+(Start-Process calc)+\u201B.exe",
	"Setup\u201C$(Start-Process calc)\u201D.exe",
	`Setup"$(Start-Process calc)".exe`,
	"Setup`$(Start-Process calc).exe",
	"Setup\r\nStart-Process calc\r\n.exe",
	"Setup');Start-Process calc;#.exe",
	"Setup</text></binding></visual></toast><!--&amp;.exe",
	"Setup\u00c1e);calc#.exe", // breaks out under cp932 in the v0.1.0 generator
	"Setup\x00\x01\x1b.exe",
}

func TestToastScriptIsConstant(t *testing.T) {
	// No dynamic data may ever be parsed as PowerShell: the script only
	// references the environment variable.
	if !strings.Contains(toastScript, "$x.LoadXml($env:"+toastEnv+")") {
		t.Fatalf("script does not load the XML from $env:%s:\n%s", toastEnv, toastScript)
	}
	for _, name := range hostileNames {
		for _, frag := range []string{name, "Start-Process", "calc"} {
			if strings.Contains(toastScript, frag) {
				t.Fatalf("script contains %q", frag)
			}
		}
	}
}

func TestToastXMLRoundTrip(t *testing.T) {
	type text struct {
		V string `xml:",chardata"`
	}
	type toast struct {
		Launch   string `xml:"launch,attr"`
		Scenario string `xml:"scenario,attr"`
		Texts    []text `xml:"visual>binding>text"`
	}
	for _, name := range hostileNames {
		for _, u := range []Urgency{Normal, Critical} {
			title := "suspicious: " + name
			body := "summary for " + name
			doc := toastXML(title, body, "/vault/reports/"+name+".html", u)
			var got toast
			if err := xml.Unmarshal([]byte(doc), &got); err != nil {
				t.Fatalf("%q: invalid XML: %v\n%s", name, err, doc)
			}
			// Control characters XML cannot carry are dropped; XML also
			// normalizes CR LF to LF.
			want := func(s string) string {
				s = strings.Map(func(r rune) rune {
					if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
						return -1
					}
					return r
				}, s)
				return strings.ReplaceAll(s, "\r\n", "\n")
			}
			if len(got.Texts) != 2 || got.Texts[0].V != want(title) || got.Texts[1].V != want(body) {
				t.Fatalf("%q: texts did not round-trip: %+v", name, got.Texts)
			}
			if got.Launch == "" || !strings.HasPrefix(got.Launch, "file:///") {
				t.Fatalf("%q: bad launch %q", name, got.Launch)
			}
			if (u == Critical) != (got.Scenario == "reminder") {
				t.Fatalf("%q: scenario %q for urgency %d", name, got.Scenario, u)
			}
		}
	}
}
