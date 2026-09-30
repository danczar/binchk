//go:build ignore

// gen_rules compresses rules/builtin.json into rules/builtin.json.gz.
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"log"
	"os"
)

func main() {
	src, err := os.ReadFile("rules/builtin.json")
	if err != nil {
		log.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(src, &v); err != nil {
		log.Fatal("rules/builtin.json: ", err)
	}
	var b bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&b, gzip.BestCompression)
	zw.Write(src)
	zw.Close()
	if err := os.WriteFile("rules/builtin.json.gz", b.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
}
