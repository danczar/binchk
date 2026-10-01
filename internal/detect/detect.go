// Package detect identifies executable binary formats from magic bytes.
package detect

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Format string

const (
	Unknown  Format = ""
	ELF      Format = "ELF"
	MachO    Format = "Mach-O"
	MachOFat Format = "Mach-O (universal)"
	PE       Format = "PE"
	// Containers: inspected by mounting / expanding them (macOS only).
	DiskImage    Format = "Apple disk image"
	InstallerPkg Format = "Installer package"
	AppBundle    Format = "Application bundle"
)

// IsContainer reports whether f holds other files rather than code.
func (f Format) IsContainer() bool { return f == DiskImage || f == InstallerPkg || f == AppBundle }

// IsAppBundle reports whether path is a macOS application bundle directory.
func IsAppBundle(path string) bool {
	if !strings.EqualFold(filepath.Ext(path), ".app") {
		return false
	}
	st, err := os.Stat(path)
	if err != nil || !st.IsDir() {
		return false
	}
	for _, p := range []string{"Contents/Info.plist", "Contents/MacOS"} {
		if _, err := os.Stat(filepath.Join(path, p)); err == nil {
			return true
		}
	}
	return false
}

// SniffPath is SniffFile that also recognises application bundles.
func SniffPath(path string) Format {
	if IsAppBundle(path) {
		return AppBundle
	}
	return SniffFile(path)
}

// Sniff inspects the start of a file. r must cover at least the first 64
// bytes to detect ELF/Mach-O; PE detection follows e_lfanew.
func Sniff(r io.ReaderAt, size int64) Format {
	var h [64]byte
	n, _ := r.ReadAt(h[:], 0)
	if n < 4 {
		return Unknown
	}
	// Leading magic wins: loaders ignore trailing bytes, so an appended
	// "koly" trailer must never turn an executable into a disk image.
	if f := sniffMagic(r, h[:n], size); f != Unknown {
		return f
	}
	if HasUDIFTrailer(r, size) {
		return DiskImage
	}
	return Unknown
}

// HasUDIFTrailer reports whether the file ends with a UDIF "koly" trailer:
// signature, version 4 and a 512-byte header size, as hdiutil writes them.
func HasUDIFTrailer(r io.ReaderAt, size int64) bool {
	if size < 1024 {
		return false
	}
	var k [12]byte
	if _, err := r.ReadAt(k[:], size-512); err != nil {
		return false
	}
	return string(k[:4]) == "koly" && binary.BigEndian.Uint32(k[4:8]) == 4 && binary.BigEndian.Uint32(k[8:12]) == 512
}

// sniffMagic classifies a file by its leading bytes h (at least 4).
func sniffMagic(r io.ReaderAt, h []byte, size int64) Format {
	n := len(h)
	be := binary.BigEndian.Uint32(h[:4])
	switch {
	case n >= 8 && string(h[:8]) == "encrcdsa":
		// Encrypted disk images: the UDIF trailer is inside the ciphertext.
		return DiskImage
	case string(h[:4]) == "xar!":
		// Flat installer packages are xar archives.
		return InstallerPkg
	case h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F':
		return ELF
	case be == 0xfeedface || be == 0xfeedfacf || be == 0xcefaedfe || be == 0xcffaedfe:
		return MachO
	case be == 0xcafebabe || be == 0xcafebabf:
		// 0xcafebabe is shared with Java class files, whose next word is a
		// class-file version (>= 45). Fat headers hold a small arch count.
		if n >= 8 {
			if narch := binary.BigEndian.Uint32(h[4:8]); narch > 0 && narch < 32 {
				return MachOFat
			}
		}
		return Unknown
	case h[0] == 'M' && h[1] == 'Z':
		if n < 64 {
			return Unknown
		}
		off := int64(binary.LittleEndian.Uint32(h[0x3c:0x40]))
		if off <= 0 || off+4 > size || off > 1<<20 {
			return Unknown
		}
		var sig [4]byte
		if _, err := r.ReadAt(sig[:], off); err != nil {
			return Unknown
		}
		if sig == [4]byte{'P', 'E', 0, 0} {
			return PE
		}
	}
	return Unknown
}

// SniffFile opens path and sniffs it. It never returns an error: unreadable
// files are simply not binaries as far as binchk is concerned.
func SniffFile(path string) Format {
	f, err := os.Open(path)
	if err != nil {
		return Unknown
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return Unknown
	}
	return Sniff(f, st.Size())
}
