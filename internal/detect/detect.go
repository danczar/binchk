// Package detect identifies executable binary formats from magic bytes.
package detect

import (
	"bytes"
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
	// A script with a trailer is still a DiskImage here (so watchers pick
	// it up); callers check UDIFPolyglot to inspect its leading side too.
	if HasUDIFTrailer(r, size) || hasUDIFHeader(r, size) {
		return DiskImage
	}
	return Unknown
}

// HasUDIFTrailer reports whether the file ends with a UDIF "koly" trailer
// hdiutil would accept. Only what hdiutil itself checks is required: the
// signature, a nonzero version and an XML plist range inside the file.
// hdiutil ignores the header size and the data fork length (it mounts
// images with a header size of 0 or 0x400, or a data fork length past the
// end of the file), so neither may be used to reject a trailer.
func HasUDIFTrailer(r io.ReaderAt, size int64) bool {
	return kolyAt(r, size, size-512)
}

// hasUDIFHeader reports whether the file starts with a koly block, which
// hdiutil also accepts (its offsets then count from the file start too).
func hasUDIFHeader(r io.ReaderAt, size int64) bool {
	return kolyAt(r, size, 0)
}

// kolyAt reports whether a koly block hdiutil accepts sits at offset at.
func kolyAt(r io.ReaderAt, size, at int64) bool {
	if size < 512 || at < 0 {
		return false
	}
	var k [512]byte
	if _, err := r.ReadAt(k[:], at); err != nil {
		return false
	}
	if string(k[:4]) != "koly" || binary.BigEndian.Uint32(k[4:8]) == 0 {
		return false
	}
	// The plist may run into the trailer itself: hdiutil reads up to EOF.
	off, n := binary.BigEndian.Uint64(k[0xD8:]), binary.BigEndian.Uint64(k[0xE0:])
	end := uint64(size)
	return off <= end && n <= end-off
}

// SniffLeading classifies a file by its leading bytes alone, ignoring any
// UDIF trailer. Scripts ("#!") are Unknown here as in Sniff.
func SniffLeading(r io.ReaderAt, size int64) Format {
	var h [64]byte
	n, _ := r.ReadAt(h[:], 0)
	if n < 4 {
		return Unknown
	}
	return sniffMagic(r, h[:n], size)
}

// HasShebang reports whether h starts with "#!", optionally after a UTF-8
// byte order mark (a shell still runs such a file as a script).
func HasShebang(h []byte) bool {
	h = bytes.TrimPrefix(h, []byte("\xef\xbb\xbf"))
	return len(h) >= 2 && h[0] == '#' && h[1] == '!'
}

// UDIFPolyglot reports whether the file ends with a valid UDIF trailer but
// starts with something other than the image's own data: executable or
// container magic, a "#!" script, or any bytes before the data fork. Such a
// file both mounts and runs (or opens as the other format), so both sides
// must be inspected. Images hdiutil writes start their data fork at 0 with
// none of those signatures. A plain image is not a polyglot here, but its
// own bytes still need scanning: a raw image's leading sectors are the
// author's to fill, and a shell runs text there even without "#!".
func UDIFPolyglot(r io.ReaderAt, size int64) bool {
	if !HasUDIFTrailer(r, size) {
		return false
	}
	var h [5]byte
	if n, _ := r.ReadAt(h[:], 0); HasShebang(h[:n]) {
		return true
	}
	if SniffLeading(r, size) != Unknown {
		return true
	}
	var off [8]byte
	if _, err := r.ReadAt(off[:], size-512+0x18); err != nil {
		return true
	}
	return binary.BigEndian.Uint64(off[:]) != 0
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
