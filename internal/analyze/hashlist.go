package analyze

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// HashList is a concurrency-safe set of SHA-256 hashes with notes, backed by
// a text file of "sha256 [note]" lines ('#' starts a comment).
type HashList struct {
	mu   sync.RWMutex
	m    map[string]string
	path string
}

// LoadHashList reads path; a missing file yields an empty list that will be
// created on the first Add.
func LoadHashList(path string) *HashList {
	h := &HashList{m: map[string]string{}, path: path}
	if path == "" {
		return h
	}
	f, err := os.Open(path)
	if err != nil {
		return h
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		sha, note, _ := strings.Cut(line, " ")
		if len(sha) == 64 {
			h.m[strings.ToLower(sha)] = strings.TrimSpace(note)
		}
	}
	return h
}

func (h *HashList) Lookup(sha string) (string, bool) {
	if h == nil || sha == "" {
		return "", false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	n, ok := h.m[sha]
	return n, ok
}

// Add records sha and appends it to the backing file.
func (h *HashList) Add(sha, note string) error {
	if h == nil || len(sha) != 64 {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.m[sha]; ok {
		return nil
	}
	h.m[sha] = note
	if h.path == "" {
		return nil
	}
	f, err := os.OpenFile(h.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s %s (%s)\n", sha, strings.ReplaceAll(note, "\n", " "), time.Now().Format("2006-01-02"))
	return err
}
