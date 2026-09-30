// Package mapfile memory-maps files read-only so analysis never copies the
// binary into the Go heap.
package mapfile

import (
	"errors"
	"os"
)

// File is a read-only mapping. Data must not be used after Close.
type File struct {
	Data  []byte
	f     *os.File
	unmap func() error
}

// Open maps path. Empty files yield an empty Data slice with no mapping.
func Open(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("not a regular file")
	}
	size := st.Size()
	if size == 0 {
		return &File{f: f}, nil
	}
	if int64(int(size)) != size {
		f.Close()
		return nil, errors.New("file too large to map")
	}
	data, unmap, err := mmap(f, int(size))
	if err != nil {
		f.Close()
		return nil, err
	}
	return &File{Data: data, f: f, unmap: unmap}, nil
}

func (m *File) Close() error {
	var err error
	if m.unmap != nil {
		err = m.unmap()
		m.unmap = nil
	}
	m.Data = nil
	if cerr := m.f.Close(); err == nil {
		err = cerr
	}
	return err
}
