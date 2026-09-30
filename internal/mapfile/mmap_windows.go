package mapfile

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func mmap(f *os.File, size int) ([]byte, func() error, error) {
	h, err := windows.CreateFileMapping(windows.Handle(f.Fd()), nil, windows.PAGE_READONLY, 0, 0, nil)
	if err != nil {
		return nil, nil, os.NewSyscallError("CreateFileMapping", err)
	}
	addr, err := windows.MapViewOfFile(h, windows.FILE_MAP_READ, 0, 0, uintptr(size))
	if err != nil {
		windows.CloseHandle(h)
		return nil, nil, os.NewSyscallError("MapViewOfFile", err)
	}
	// addr is OS-allocated memory outside the Go heap; convert without
	// tripping vet's uintptr->Pointer check.
	data := unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&addr))), size)
	return data, func() error {
		err := windows.UnmapViewOfFile(addr)
		windows.CloseHandle(h)
		return err
	}, nil
}
