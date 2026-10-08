package findertag

import (
	"reflect"
	"testing"
)

func TestMerge(t *testing.T) {
	for _, tc := range []struct {
		in      []string
		verdict string
		want    []string
		changed bool
	}{
		{nil, "", nil, false},
		{nil, "Suspicious", []string{"binchk: Suspicious\n7"}, true},
		{[]string{"Work", "Red\n6"}, "Malicious", []string{"Work", "Red\n6", "binchk: Malicious\n6"}, true},
		{[]string{"Work", "binchk: Suspicious\n7", "Home\n4"}, "Malicious", []string{"Work", "Home\n4", "binchk: Malicious\n6"}, true},
		{[]string{"Work", "binchk: Malicious\n6"}, "Malicious", []string{"Work", "binchk: Malicious\n6"}, false},
		{[]string{"binchk: Malicious\n6", "binchk: Malicious\n6"}, "Malicious", []string{"binchk: Malicious\n6"}, true},
		{[]string{"Work", "binchk: Suspicious"}, "", []string{"Work"}, true},
		{[]string{"Work", "binchk: Suspicious\n7"}, "Clean", []string{"Work", "binchk: Clean\n2"}, true},
		{[]string{"binchk"}, "", []string{"binchk"}, false}, // not ours: no prefix
	} {
		got, changed := merge(tc.in, tc.verdict)
		if !reflect.DeepEqual(got, tc.want) || changed != tc.changed {
			t.Errorf("merge(%q, %q) = %q, %v; want %q, %v", tc.in, tc.verdict, got, changed, tc.want, tc.changed)
		}
	}
}

func TestTag(t *testing.T) {
	for v, want := range map[string]string{
		"Suspicious": "binchk: Suspicious\n7",
		"Malicious":  "binchk: Malicious\n6",
		"Clean":      "binchk: Clean\n2",
	} {
		if got := Tag(v); got != want {
			t.Errorf("Tag(%s) = %q", v, got)
		}
	}
}
