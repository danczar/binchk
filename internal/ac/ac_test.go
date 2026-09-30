package ac

import (
	"bytes"
	"math/rand"
	"sort"
	"testing"
)

type hit struct{ id, start int }

func naive(pats []Pattern, data []byte, minStart int) []hit {
	var out []hit
	lower := asciiLower(data)
	for id, p := range pats {
		needle, hay := p.Bytes, data
		if p.NoCase {
			needle, hay = asciiLower(p.Bytes), lower
		}
		for i := minStart; i+len(needle) <= len(hay); i++ {
			if bytes.Equal(hay[i:i+len(needle)], needle) {
				out = append(out, hit{id, i})
			}
		}
	}
	return out
}

func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = fold(c)
	}
	return out
}

func collect(m *Matcher, data []byte, minStart int) []hit {
	var out []hit
	m.Scan(data, minStart, func(id, start int) { out = append(out, hit{id, start}) })
	return out
}

func sortHits(h []hit) {
	sort.Slice(h, func(i, j int) bool {
		if h[i].start != h[j].start {
			return h[i].start < h[j].start
		}
		return h[i].id < h[j].id
	})
}

func TestMatchesNaive(t *testing.T) {
	pats := []Pattern{
		{Bytes: []byte("he"), NoCase: true},
		{Bytes: []byte("she"), NoCase: true},
		{Bytes: []byte("his")},
		{Bytes: []byte("hers"), NoCase: true},
		{Bytes: []byte("VirtualAllocEx")},
		{Bytes: []byte{0, 1, 2, 0xff}},
		{Bytes: []byte("aaa"), NoCase: true},
	}
	m := Build(pats)
	rng := rand.New(rand.NewSource(1))
	alphabet := []byte("hHeEsSirRaA\x00\x01\x02\xffVirtualAllocEx")
	for iter := 0; iter < 200; iter++ {
		data := make([]byte, rng.Intn(400))
		for i := range data {
			data[i] = alphabet[rng.Intn(len(alphabet))]
		}
		minStart := 0
		if len(data) > 0 {
			minStart = rng.Intn(len(data))
		}
		got, want := collect(m, data, minStart), naive(pats, data, minStart)
		sortHits(got)
		sortHits(want)
		if len(got) != len(want) {
			t.Fatalf("iter %d: got %d hits want %d", iter, len(got), len(want))
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("iter %d: hit %d got %v want %v", iter, i, got[i], want[i])
			}
		}
	}
}

func TestCaseSensitive(t *testing.T) {
	m := Build([]Pattern{{Bytes: []byte("UPX!")}})
	if n := len(collect(m, []byte("upx! UPX! Upx!"), 0)); n != 1 {
		t.Fatalf("want 1 exact match, got %d", n)
	}
}

func BenchmarkScan(b *testing.B) {
	var pats []Pattern
	words := []string{"virtualallocex", "writeprocessmemory", "createremotethread", "stratum+tcp://",
		"vssadmin delete shadows", "mimikatz", "/etc/ld.so.preload", "powershell -enc", "login data",
		"wallet.dat", "discord.com/api/webhooks", "api.telegram.org/bot", "launchagents"}
	for i := 0; i < 20; i++ {
		for _, w := range words {
			pats = append(pats, Pattern{Bytes: []byte(w + string(rune('a'+i))), NoCase: true})
		}
	}
	m := Build(pats)
	data := make([]byte, 16<<20)
	rand.New(rand.NewSource(2)).Read(data)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Scan(data, 0, func(int, int) {})
	}
}
