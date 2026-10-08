package tray

import (
	"testing"

	"github.com/danczar/binchk/internal/index"
)

func TestWorstVerdict(t *testing.T) {
	e := func(v string, safe bool) *index.Entry { return &index.Entry{Verdict: v, MarkedSafe: safe} }
	for _, tc := range []struct {
		in   []*index.Entry
		want string
	}{
		{nil, ""},
		{[]*index.Entry{e("Clean", false), e("Error", false)}, ""},
		{[]*index.Entry{e("Clean", false), e("Suspicious", false)}, "Suspicious"},
		{[]*index.Entry{e("Suspicious", false), e("Malicious", false), e("Clean", false)}, "Malicious"},
		{[]*index.Entry{e("Malicious", true), e("Suspicious", false)}, "Suspicious"},
		{[]*index.Entry{e("Malicious", true), e("Suspicious", true)}, ""},
	} {
		if got := worstVerdict(tc.in); got != tc.want {
			t.Errorf("worstVerdict = %q, want %q", got, tc.want)
		}
	}
}
