// Package ac implements a multi-pattern Aho–Corasick matcher compiled to a
// dense DFA over byte equivalence classes. All signatures are matched in a
// single pass over the input, which is what lets binchk scan hundreds of
// megabytes per second per core regardless of how many rules are loaded.
package ac

import "bytes"

// Pattern is a byte sequence to find. NoCase patterns match ASCII letters
// case-insensitively; others must match exactly.
type Pattern struct {
	Bytes  []byte
	NoCase bool
}

// Matcher is immutable after Build and safe for concurrent use.
type Matcher struct {
	class    [256]uint8 // raw input byte -> equivalence class (case folded)
	nclass   int
	trans    []int32 // state*nclass + class -> next state
	firstOut int32   // states >= firstOut have at least one output
	outStart []int32 // indexed by state-firstOut
	outList  []int32
	pats     []Pattern
	maxLen   int
}

func fold(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

// Build compiles the patterns. Empty patterns are ignored.
func Build(pats []Pattern) *Matcher {
	m := &Matcher{pats: pats}

	// Byte classes: every distinct folded byte used by a pattern gets its own
	// class; everything else shares class 0. Keeps the DFA table small.
	var used [256]bool
	for _, p := range pats {
		for _, b := range p.Bytes {
			used[fold(b)] = true
		}
		if len(p.Bytes) > m.maxLen {
			m.maxLen = len(p.Bytes)
		}
	}
	var folded [256]uint8
	n := 1
	for b := 0; b < 256; b++ {
		if used[b] {
			folded[b] = uint8(n)
			n++
		}
	}
	for b := 0; b < 256; b++ {
		m.class[b] = folded[fold(byte(b))]
	}
	m.nclass = n

	// Trie.
	type node struct {
		next map[uint8]int32
		out  []int32
		fail int32
	}
	nodes := []node{{next: map[uint8]int32{}}}
	for id, p := range pats {
		if len(p.Bytes) == 0 {
			continue
		}
		s := int32(0)
		for _, b := range p.Bytes {
			c := m.class[b]
			nx, ok := nodes[s].next[c]
			if !ok {
				nx = int32(len(nodes))
				nodes = append(nodes, node{next: map[uint8]int32{}})
				nodes[s].next[c] = nx
			}
			s = nx
		}
		nodes[s].out = append(nodes[s].out, int32(id))
	}

	// BFS to compute failure links and the full DFA.
	ns := len(nodes)
	trans := make([]int32, ns*n)
	order := make([]int32, 0, ns)
	for c := 0; c < n; c++ {
		if nx, ok := nodes[0].next[uint8(c)]; ok {
			trans[c] = nx
			nodes[nx].fail = 0
			order = append(order, nx)
		}
	}
	for i := 0; i < len(order); i++ {
		s := order[i]
		f := nodes[s].fail
		nodes[s].out = append(nodes[s].out, nodes[f].out...)
		for c := 0; c < n; c++ {
			if nx, ok := nodes[s].next[uint8(c)]; ok {
				nodes[nx].fail = trans[int(f)*n+c]
				trans[int(s)*n+c] = nx
				order = append(order, nx)
			} else {
				trans[int(s)*n+c] = trans[int(f)*n+c]
			}
		}
	}

	// Renumber so that every accepting state sorts after every
	// non-accepting one: the hot loop then needs a single compare.
	remap := make([]int32, ns)
	next := int32(0)
	for s := 0; s < ns; s++ {
		if len(nodes[s].out) == 0 {
			remap[s] = next
			next++
		}
	}
	m.firstOut = next
	for s := 0; s < ns; s++ {
		if len(nodes[s].out) > 0 {
			remap[s] = next
			next++
		}
	}
	m.trans = make([]int32, ns*n)
	for s := 0; s < ns; s++ {
		for c := 0; c < n; c++ {
			// Store pre-multiplied row offsets so the hot loop needs no multiply.
			m.trans[int(remap[s])*n+c] = remap[trans[s*n+c]] * int32(n)
		}
	}
	m.outStart = make([]int32, ns-int(m.firstOut)+1)
	for s := 0; s < ns; s++ {
		if len(nodes[s].out) == 0 {
			continue
		}
		m.outStart[remap[s]-m.firstOut] = int32(len(nodes[s].out))
	}
	// prefix sums
	sum := int32(0)
	for i := range m.outStart {
		c := m.outStart[i]
		m.outStart[i] = sum
		sum += c
	}
	m.outList = make([]int32, sum)
	fill := make([]int32, len(m.outStart))
	for s := 0; s < ns; s++ {
		if len(nodes[s].out) == 0 {
			continue
		}
		k := remap[s] - m.firstOut
		copy(m.outList[m.outStart[k]+fill[k]:], nodes[s].out)
		fill[k] += int32(len(nodes[s].out))
	}
	return m
}

// MaxLen is the longest pattern length; callers scanning in chunks must
// overlap chunks by MaxLen-1 bytes.
func (m *Matcher) MaxLen() int { return m.maxLen }

// Len returns the number of patterns.
func (m *Matcher) Len() int { return len(m.pats) }

// Scan runs the matcher over data and calls fn(patternID, startOffset) for
// every match whose start offset is >= minStart. Offsets are relative to data.
func (m *Matcher) Scan(data []byte, minStart int, fn func(id int, start int)) {
	if m.maxLen == 0 {
		return
	}
	trans, class, n := m.trans, &m.class, int32(m.nclass)
	firstOut := m.firstOut * n
	s := int32(0) // row offset of the current state
	for i := 0; i < len(data); i++ {
		s = trans[s+int32(class[data[i]])]
		if s < firstOut {
			continue
		}
		k := (s - firstOut) / n
		for _, id := range m.outList[m.outStart[k]:m.outStart[k+1]] {
			p := &m.pats[id]
			start := i + 1 - len(p.Bytes)
			if start < minStart {
				continue
			}
			if !p.NoCase && !bytes.Equal(data[start:i+1], p.Bytes) {
				continue
			}
			fn(int(id), start)
		}
	}
}
