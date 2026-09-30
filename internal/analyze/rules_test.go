package analyze

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"testing"
)

// The embedded blob must match the editable JSON; run `go generate`.
func TestBuiltinRulesInSync(t *testing.T) {
	src, err := os.ReadFile("rules/builtin.json")
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(builtinRulesGz))
	if err != nil {
		t.Fatal(err)
	}
	emb, _ := io.ReadAll(zr)
	if !bytes.Equal(src, emb) {
		t.Fatal("rules/builtin.json.gz is stale: run `go generate ./internal/analyze`")
	}
	if _, err := compileRules(builtinRules); err != nil {
		t.Fatal(err)
	}
}
