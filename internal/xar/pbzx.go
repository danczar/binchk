package xar

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"

	"github.com/ulikunitz/xz"
)

// pbzx is Apple's payload format: "pbzx", a u64 chunk size, then chunks of
// (u64 flags, u64 length, data) where each chunk is an xz stream, or raw
// bytes when it could not be compressed.
type pbzx struct {
	ctx context.Context
	r   io.Reader
	cur io.Reader
	eof bool
}

const maxChunk = 64 << 20

func newPBZX(ctx context.Context, r io.Reader) (io.Reader, error) {
	var hdr [12]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	return &pbzx{ctx: ctx, r: r}, nil
}

func (p *pbzx) next() error {
	var h [16]byte
	if _, err := io.ReadFull(p.r, h[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return io.EOF
		}
		return err
	}
	n := binary.BigEndian.Uint64(h[8:])
	if n > maxChunk {
		return errors.New("pbzx: chunk too large")
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(p.r, data); err != nil {
		return err
	}
	if bytes.HasPrefix(data, []byte{0xfd, '7', 'z', 'X', 'Z', 0}) {
		xr, err := xz.NewReader(bytes.NewReader(data))
		if err != nil {
			return err
		}
		p.cur = xr
	} else {
		p.cur = bytes.NewReader(data)
	}
	return nil
}

func (p *pbzx) Read(b []byte) (int, error) {
	for {
		if p.eof {
			return 0, io.EOF
		}
		// A run of chunks that yield no data never returns to the caller,
		// so the deadline is checked here.
		if err := p.ctx.Err(); err != nil {
			return 0, err
		}
		if p.cur != nil {
			n, err := p.cur.Read(b)
			if n > 0 {
				return n, nil
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return 0, err
			}
			p.cur = nil
		}
		if err := p.next(); err != nil {
			if errors.Is(err, io.EOF) {
				p.eof = true
				continue
			}
			return 0, err
		}
	}
}
