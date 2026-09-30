package analyze

import (
	"bytes"
	"io"
)

func byteReaderAt(b []byte) io.ReaderAt { return bytes.NewReader(b) }
