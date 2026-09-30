package container

import (
	"encoding/xml"
	"os"
	"strconv"
)

// readXMLPlist extracts top-level scalar keys from an XML plist — the
// fallback where plutil is unavailable.
func readXMLPlist(p string) (map[string]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	d := xml.NewDecoder(f)
	m := map[string]string{}
	depth, key := 0, ""
	for {
		tok, err := d.Token()
		if err != nil {
			return m, nil
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth != 3 { // plist > dict > (key|value)
				continue
			}
			switch t.Name.Local {
			case "key":
				var s string
				d.DecodeElement(&s, &t)
				key = s
				depth--
			case "string", "integer", "real":
				var s string
				d.DecodeElement(&s, &t)
				m[key] = s
				depth--
			case "true", "false":
				m[key] = t.Name.Local
			}
		case xml.EndElement:
			depth--
		}
	}
}

func jsonNum(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }
