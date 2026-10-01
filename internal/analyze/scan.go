package analyze

import (
	"bytes"
	"context"
	"math"
	"math/bits"
	"sort"
	"strings"
	"sync"
)

const (
	minASCII = 6 // minimum printable run counted as a string
	minWide  = 6
	maxIOCs  = 100
)

// contentResult is the merged output of the parallel content pass.
type contentResult struct {
	hist      [256]uint64
	blockSize int
	blocks    []float64 // entropy per block, in file order
	hits      []uint32  // per AC pattern id
	strings   int
	iocs      iocSet
}

type chunkOut struct {
	wide    []byte // scratch for UTF-16 -> ASCII
	hist    [256]uint64
	blocks  []float64
	hits    []uint32
	strings int
	iocs    iocSet
}

// scanContent splits data into block-aligned chunks and processes them on
// all cores. Each chunk computes a byte histogram per block (entropy map),
// extracts ASCII and UTF-16LE strings for IOC classification and runs the
// Aho–Corasick signature matcher. Chunks are small enough to stay in L2.
func scanContent(ctx context.Context, data []byte, rs *ruleSet, workers int) (*contentResult, error) {
	size := len(data)
	blockSize := 4096
	for blockSize*512 < size {
		blockSize <<= 1
	}
	chunkSize := blockSize
	for chunkSize < 1<<20 {
		chunkSize <<= 1
	}
	nchunks := (size + chunkSize - 1) / chunkSize
	if nchunks == 0 {
		nchunks = 1
	}
	if workers > nchunks {
		workers = nchunks
	}
	outs := make([]*chunkOut, nchunks)
	next := make(chan int, nchunks)
	for i := 0; i < nchunks; i++ {
		next <- i
	}
	close(next)
	overlap := rs.m.MaxLen() - 1
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ci := range next {
				if ctx.Err() != nil {
					return
				}
				start := ci * chunkSize
				end := min(start+chunkSize, size)
				o := &chunkOut{hits: make([]uint32, rs.m.Len())}
				// entropy per block
				for b := start; b < end; b += blockSize {
					var h [256]uint64
					histogram(data[b:min(b+blockSize, end)], &h)
					o.blocks = append(o.blocks, entropy(&h, uint64(min(b+blockSize, end)-b)))
					for k := range h {
						o.hist[k] += h[k]
					}
				}
				// Signatures: scan past the chunk end by maxLen-1 so matches
				// crossing the boundary complete here; count only matches
				// that start inside this chunk (the next chunk owns the rest).
				own := end - start
				rs.m.Scan(data[start:min(end+overlap, size)], 0, func(id, st int) {
					if st < own {
						o.hits[id]++
					}
				})
				extractStrings(data, start, end, o)
				outs[ci] = o
			}
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	res := &contentResult{blockSize: blockSize, hits: make([]uint32, rs.m.Len())}
	for _, o := range outs {
		for k := range o.hist {
			res.hist[k] += o.hist[k]
		}
		res.blocks = append(res.blocks, o.blocks...)
		for k, v := range o.hits {
			res.hits[k] += v
		}
		res.strings += o.strings
		res.iocs.merge(&o.iocs)
	}
	return res, nil
}

// histogram adds byte counts of b to h using four interleaved tables to
// avoid store-to-load stalls on runs of identical bytes.
func histogram(b []byte, h *[256]uint64) {
	for len(b) > 0 {
		n := min(len(b), 1<<30) // keep uint32 counters from overflowing
		var t [4][256]uint32
		p := b[:n]
		i := 0
		for ; i+4 <= len(p); i += 4 {
			t[0][p[i]]++
			t[1][p[i+1]]++
			t[2][p[i+2]]++
			t[3][p[i+3]]++
		}
		for ; i < len(p); i++ {
			t[0][p[i]]++
		}
		for k := 0; k < 256; k++ {
			h[k] += uint64(t[0][k]) + uint64(t[1][k]) + uint64(t[2][k]) + uint64(t[3][k])
		}
		b = b[n:]
	}
}

// entropy returns Shannon entropy in bits per byte (0..8).
func entropy(h *[256]uint64, total uint64) float64 {
	if total == 0 {
		return 0
	}
	t := float64(total)
	e := 0.0
	for _, c := range h {
		if c != 0 {
			p := float64(c) / t
			e -= p * math.Log2(p)
		}
	}
	return e
}

func entropyOf(b []byte) float64 {
	var h [256]uint64
	histogram(b, &h)
	return entropy(&h, uint64(len(b)))
}

var printable = func() (t [256]bool) {
	for c := 0x20; c < 0x7f; c++ {
		t[c] = true
	}
	t['\t'] = true
	return
}()

var printable8 = func() (t [256]uint8) {
	for c := 0; c < 256; c++ {
		if printable[c] {
			t[c] = 1
		}
	}
	return
}()

// extractStrings finds printable runs owned by [start,end): a run belongs to
// the chunk it starts in and is followed past end if it crosses it.
//
// The loops are written to be nearly branch-free — run = (run+1)*isPrintable
// — because on binary data printable/non-printable bytes alternate
// unpredictably and a branchy loop spends most of its time mispredicting.
// The only branch is "a long-enough run just ended", which is rare.
// noEmit starts a run counter so low that it cannot reach a minimum string
// length within one chunk (chunks are far below 2 GiB). It must fit a 32-bit
// int: binchk also builds for 386 and arm.
const noEmit = math.MinInt32

func extractStrings(data []byte, start, end int, o *chunkOut) {
	// ASCII
	run := 0
	if start > 0 && printable[data[start-1]] {
		run = noEmit // continuation of the previous chunk's run: never emit
	}
	// Test run length first: that branch is almost always false and so
	// well predicted; p==0 alone is a coin flip on binary data.
	chunk := data[start:end]
	for k, c := range chunk {
		p := int(printable8[c])
		if run >= minASCII && p == 0 {
			o.emitASCII(data[start+k-run : start+k])
		}
		run = (run + 1) * p
	}
	i := end
	if run > 0 {
		for i < len(data) && printable[data[i]] {
			i++
			run++
		}
		if run >= minASCII {
			o.emitASCII(data[i-run : i])
		}
	}

	// UTF-16LE at even offsets (start is block aligned, hence even).
	isW := func(k int) int {
		if k+1 < len(data) && data[k+1] == 0 {
			return int(printable8[data[k]])
		}
		return 0
	}
	run = 0
	if start >= 2 && isW(start-2) == 1 {
		run = noEmit
	}
	lim := min(end, len(data)-1)
	i = start
	for ; i < lim; i += 2 {
		p := int(printable8[data[i]]) & int(b2i(data[i+1] == 0))
		if run >= minWide && p == 0 {
			o.emitWide(data[i-2*run : i])
		}
		run = (run + 1) * p
	}
	if run > 0 {
		for isW(i) == 1 {
			i += 2
			run++
		}
		if run >= minWide {
			o.emitWide(data[i-2*run : i])
		}
	}
}

func b2i(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func (o *chunkOut) emitASCII(s []byte) {
	o.strings++
	o.iocs.classify(s[:min(len(s), 4096)])
}

func (o *chunkOut) emitWide(s []byte) {
	o.strings++
	n := min(len(s)/2, 4096)
	o.wide = o.wide[:0]
	for k := 0; k < n; k++ {
		o.wide = append(o.wide, s[2*k])
	}
	o.iocs.classify(o.wide)
}

// ---- IOC classification ----

type iocSet struct {
	urls, ips, onions, crypto map[string]struct{}
}

func addCapped(m *map[string]struct{}, s string) {
	if *m == nil {
		*m = map[string]struct{}{}
	}
	if len(*m) < maxIOCs {
		(*m)[s] = struct{}{}
	}
}

func (s *iocSet) merge(o *iocSet) {
	for k := range o.urls {
		addCapped(&s.urls, k)
	}
	for k := range o.ips {
		addCapped(&s.ips, k)
	}
	for k := range o.onions {
		addCapped(&s.onions, k)
	}
	for k := range o.crypto {
		addCapped(&s.crypto, k)
	}
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Hosts that appear in nearly every signed binary or XML manifest; listing
// them as indicators would only bury the interesting ones.
var benignHosts = []string{
	"w3.org", "schemas.microsoft.com", "schemas.openxmlformats.org", "ns.adobe.com", "digicert.com", "verisign.com",
	"symantec.com", "symcb.com", "symcd.com", "sectigo.com", "comodoca.com", "usertrust.com", "globalsign.com", "globalsign.net",
	"entrust.net", "apple.com", "microsoft.com", "purl.org", "xml.org", "openssl.org", "example.com", "example.org", "localhost",
	"thawte.com", "godaddy.com", "letsencrypt.org", "identrust.com", "xmlsoap.org", "ietf.org", "unicode.org", "gnu.org",
	"mozilla.org", "json-schema.org", "certum.pl", "ssl.com", "amazontrust.com", "pki.goog",
}

var urlSafe = func() (t [256]bool) {
	for _, c := range []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=%") {
		t[c] = true
	}
	return
}()

// Longest first so "https" wins over "http" and "wss" over "ws".
var urlSchemes = []string{"https", "http", "wss", "ftp", "tcp", "udp", "ws"}

func isAlpha(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func (s *iocSet) classify(str []byte) {
	if len(str) < 7 {
		return
	}
	if bytes.Contains(str, []byte("://")) {
		s.findURLs(str)
	}
	if bytes.IndexByte(str, '.') >= 0 {
		s.findIPs(str)
		if bytes.Contains(str, []byte(".onion")) {
			s.findOnions(str)
		}
	}
	if len(str) >= 42 {
		s.findCrypto(str)
	}
}

func (s *iocSet) findURLs(str []byte) {
	for off := 0; ; {
		k := bytes.Index(str[off:], []byte("://"))
		if k < 0 {
			return
		}
		k += off
		b := k
		for b > 0 && isAlpha(str[b-1]) {
			b--
		}
		// Match the scheme as a suffix: without NUL separators (Go string
		// data) the previous string's tail runs straight into "http".
		letters := strings.ToLower(string(str[b:k]))
		scheme := ""
		for _, sc := range urlSchemes {
			if strings.HasSuffix(letters, sc) {
				scheme = sc
				break
			}
		}
		e := k + 3
		for e < len(str) && urlSafe[str[e]] {
			e++
		}
		off = e
		if scheme == "" {
			continue
		}
		b = k - len(scheme)
		u := str[b:e]
		host := []byte(urlHost(string(u)))
		if len(host) < 4 || bytes.IndexByte(host, '.') < 0 || benignHost(host) {
			continue
		}
		if oct, ok := parseIPv4(host); ok && !publicIP(oct) {
			continue // loopback / LAN endpoints are not indicators
		}
		addCapped(&s.urls, string(u))
	}
}

// urlHost extracts the host from scheme://[user@]host[:port][/...].
func urlHost(u string) string {
	_, h, ok := strings.Cut(u, "://")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndexByte(h, '@'); i >= 0 {
		h = h[i+1:]
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return h
}

func benignHost(host []byte) bool {
	h := string(bytes.ToLower(host))
	for _, b := range benignHosts {
		if h == b || (len(h) > len(b) && h[len(h)-len(b)-1] == '.' && h[len(h)-len(b):] == b) {
			return true
		}
	}
	return false
}

func (s *iocSet) findIPs(str []byte) {
	for i := 0; i < len(str); i++ {
		if !isDigit(str[i]) || (i > 0 && (isDigit(str[i-1]) || str[i-1] == '.' || isAlpha(str[i-1]))) {
			continue
		}
		var oct [4]int
		j, ok := i, true
		for n := 0; n < 4 && ok; n++ {
			if n > 0 {
				if j >= len(str) || str[j] != '.' {
					ok = false
					break
				}
				j++
			}
			d0 := j
			v := 0
			for j < len(str) && isDigit(str[j]) && j-d0 < 4 {
				v = v*10 + int(str[j]-'0')
				j++
			}
			if j == d0 || j-d0 > 3 || v > 255 || (j-d0 > 1 && str[d0] == '0') {
				ok = false
			}
			oct[n] = v
		}
		if !ok || (j < len(str) && (isDigit(str[j]) || isAlpha(str[j]) || (str[j] == '.' && j+1 < len(str) && isDigit(str[j+1])))) {
			continue
		}
		if !publicIP(oct) {
			i = j
			continue
		}
		ip := str[i:j]
		if j < len(str) && str[j] == ':' {
			p, port := j+1, 0
			for p < len(str) && isDigit(str[p]) && p-j <= 5 {
				port = port*10 + int(str[p]-'0')
				p++
			}
			if p > j+1 && port > 0 && port < 65536 {
				ip = str[i:p]
			}
		}
		addCapped(&s.ips, string(ip))
		i = j
	}
}

func parseIPv4(b []byte) ([4]int, bool) {
	var o [4]int
	parts := bytes.Split(b, []byte("."))
	if len(parts) != 4 {
		return o, false
	}
	for i, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return o, false
		}
		for _, c := range p {
			if !isDigit(c) {
				return o, false
			}
			o[i] = o[i]*10 + int(c-'0')
		}
		if o[i] > 255 {
			return o, false
		}
	}
	return o, true
}

func publicIP(o [4]int) bool {
	switch {
	case o[0] == 0, o[0] == 10, o[0] == 127, o[0] >= 224:
		return false
	case o[0] == 169 && o[1] == 254, o[0] == 192 && o[1] == 168, o[0] == 172 && o[1] >= 16 && o[1] < 32:
		return false
	case o[0] == 100 && o[1] >= 64 && o[1] < 128: // CGNAT
		return false
	case o[1] == 0 && o[2] == 0 && o[3] == 0: // "8.0.0.0"-style versions
		return false
	case o[0] <= 2 && o[1] < 40: // ASN.1 OIDs such as 2.5.29.37
		return false
	case o[0] == 192 && o[1] == 0 && o[2] == 2, o[0] == 198 && o[1] == 51 && o[2] == 100, o[0] == 203 && o[1] == 0 && o[2] == 113:
		return false // RFC 5737 documentation ranges
	case o[0] == 198 && (o[1] == 18 || o[1] == 19): // benchmarking
		return false
	}
	return true
}

func isB32(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7') }

func (s *iocSet) findOnions(str []byte) {
	for off := 0; ; {
		k := bytes.Index(str[off:], []byte(".onion"))
		if k < 0 {
			return
		}
		k += off
		b := k
		for b > 0 && isB32(str[b-1]) {
			b--
		}
		if n := k - b; n == 16 || n == 56 {
			addCapped(&s.onions, string(str[b:k+6]))
		}
		off = k + 6
	}
}

const bech32Chars = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var isBech32 = func() (t [256]bool) {
	for i := 0; i < len(bech32Chars); i++ {
		t[bech32Chars[i]] = true
	}
	return
}()

func isB58(c byte) bool {
	return isDigit(c) && c != '0' || (isAlpha(c) && c != 'O' && c != 'I' && c != 'l')
}

// findCrypto spots Bitcoin bech32/bech32m and Monero addresses — the
// formats clipboard hijackers and ransom notes embed. Bech32 candidates are
// checksum-verified, so they are found even when packed against other text
// (Go does not NUL-separate string data) without false positives.
func (s *iocSet) findCrypto(str []byte) {
	for i := 0; i+42 <= len(str); i++ {
		if str[i] == 'b' && str[i+1] == 'c' && str[i+2] == '1' {
			j := i + 3
			for j < len(str) && j-i < 62 && isBech32[str[j]] {
				j++
			}
			for _, n := range []int{62, 42} {
				if j-i >= n && bech32Valid(str[i+3:i+n]) {
					addCapped(&s.crypto, string(str[i:i+n]))
					i += n - 1
					break
				}
			}
			continue
		}
		if (str[i] == '4' || str[i] == '8') && (i == 0 || !(isAlpha(str[i-1]) || isDigit(str[i-1]))) {
			j := i
			for j < len(str) && isB58(str[j]) {
				j++
			}
			// Monero standard addresses: '4' + [0-9AB] + 93 base58 chars.
			if j-i == 95 && str[i] == '4' && (isDigit(str[i+1]) || str[i+1] == 'A' || str[i+1] == 'B') &&
				bits.OnesCount(uint(mixMask(str[i:j]))) == 3 && distinct(str[i:j]) >= 24 {
				addCapped(&s.crypto, string(str[i:j]))
			}
			if j > i {
				i = j - 1
			}
		}
	}
}

// bech32Valid checks the BIP-173/BIP-350 checksum of the data part of a
// "bc1..." address.
func bech32Valid(data []byte) bool {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	step := func(v uint32) {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (b>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	for _, v := range []uint32{3, 3, 0, 2, 3} { // hrp "bc" expanded
		step(v)
	}
	for _, c := range data {
		step(uint32(bech32Index[c]))
	}
	return chk == 1 || chk == 0x2bc830a3
}

var bech32Index = func() (t [256]uint8) {
	for i := 0; i < len(bech32Chars); i++ {
		t[bech32Chars[i]] = uint8(i)
	}
	return
}()

func distinct(b []byte) int {
	var seen [256]bool
	n := 0
	for _, c := range b {
		if !seen[c] {
			seen[c] = true
			n++
		}
	}
	return n
}

func mixMask(b []byte) int {
	m := 0
	for _, c := range b {
		switch {
		case isDigit(c):
			m |= 1
		case c >= 'a' && c <= 'z':
			m |= 2
		case c >= 'A' && c <= 'Z':
			m |= 4
		}
	}
	return m
}
