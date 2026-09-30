package analyze

import (
	"context"
	"math/rand"
	"sort"
	"testing"
)

// Patterns and strings straddling chunk boundaries must be found exactly once.
func TestScanChunkBoundaries(t *testing.T) {
	rs, err := compileRules([]Rule{{ID: "t", Title: "t", Category: "x", Severity: High, Strings: []string{"stratum+tcp://"}}})
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 5<<20)
	rng := rand.New(rand.NewSource(3))
	for i := range data {
		data[i] = byte(rng.Intn(0x20)) // non-printable noise: no stray strings
	}
	needle := []byte("stratum+tcp://")
	places := []int{0, 1<<20 - 5, 2<<20 - 1, 3 << 20, len(data) - len(needle)}
	for _, p := range places {
		copy(data[p:], needle)
	}
	url := []byte("see http://45.77.10.21:8080/x for details")
	copy(data[(4<<20)-10:], url)
	for _, workers := range []int{1, 3, 16} {
		cr, err := scanContent(context.Background(), data, rs, workers)
		if err != nil {
			t.Fatal(err)
		}
		total := uint32(0)
		for _, h := range cr.hits {
			total += h
		}
		if total != uint32(len(places)) {
			t.Errorf("workers=%d: %d hits, want %d", workers, total, len(places))
		}
		if cr.strings != len(places)+1 {
			t.Errorf("workers=%d: %d strings, want %d", workers, cr.strings, len(places)+1)
		}
		if got := sortedKeys(cr.iocs.urls); len(got) != 1 || got[0] != "http://45.77.10.21:8080/x" {
			t.Errorf("urls = %v", got)
		}
	}
}

func TestIOCClassify(t *testing.T) {
	var s iocSet
	for _, str := range []string{
		"GET http://evil.example.net/a.php?id=1 HTTP/1.1",
		"https://www.w3.org/2000/svg",
		"connect 8.8.8.8:53 and 10.0.0.1 and 1.2.3.4.5 and v2.10.3.4",
		"oid 2.5.29.37 visit abcdefghijklmnop.onion now",
		"pay to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq today",
		"http://ocsp.digicert.com",
	} {
		s.classify([]byte(str))
	}
	check := func(name string, got map[string]struct{}, want ...string) {
		g := sortedKeys(got)
		sort.Strings(want)
		if len(g) != len(want) {
			t.Errorf("%s = %v, want %v", name, g, want)
			return
		}
		for i := range g {
			if g[i] != want[i] {
				t.Errorf("%s = %v, want %v", name, g, want)
			}
		}
	}
	check("urls", s.urls, "http://evil.example.net/a.php?id=1")
	check("ips", s.ips, "8.8.8.8:53")
	check("onions", s.onions, "abcdefghijklmnop.onion")
	check("crypto", s.crypto, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
}

func BenchmarkScanContent(b *testing.B) {
	data := make([]byte, 64<<20)
	rand.New(rand.NewSource(1)).Read(data)
	rs, _ := compileRules(builtinRules)
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		scanContent(context.Background(), data, rs, 0+14)
	}
}
