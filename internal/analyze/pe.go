package analyze

import (
	"bytes"
	"context"
	"crypto/md5"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// formatResult is what a format analyzer contributes to the report.
type formatResult struct {
	slices   []Slice
	sig      Signature
	findings []Finding
	imphash  string
	overlay  int64
	dotnet   bool
}

var peMachines = map[uint16]string{
	0x14c: "x86", 0x8664: "x86-64", 0xaa64: "arm64", 0x1c4: "arm", 0x200: "ia64", 0xa641: "arm64ec",
}

const (
	scnCode    = 0x00000020
	scnExecute = 0x20000000
	scnRead    = 0x40000000
	scnWrite   = 0x80000000
)

func analyzePE(ctx context.Context, data []byte) (*formatResult, error) {
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	res := &formatResult{}
	bu := newFmtBudget(ctx, len(data))
	add := func(id, title, detail string, sev Severity, ev ...string) {
		res.findings = append(res.findings, Finding{ID: id, Title: title, Detail: detail, Severity: sev, Category: "structure", Evidence: ev})
	}

	sl := Slice{Arch: peMachines[f.Machine], Props: map[string]string{}}
	if sl.Arch == "" {
		sl.Arch = fmt.Sprintf("machine 0x%x", f.Machine)
	}
	var (
		entry     uint32
		imageBase uint64
		subsystem uint16
		dllChars  uint16
		dirs      []pe.DataDirectory
	)
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		sl.Bits = 32
		entry, imageBase, subsystem, dllChars = oh.AddressOfEntryPoint, uint64(oh.ImageBase), oh.Subsystem, oh.DllCharacteristics
		dirs = oh.DataDirectory[:min(int(oh.NumberOfRvaAndSizes), 16)]
	case *pe.OptionalHeader64:
		sl.Bits = 64
		entry, imageBase, subsystem, dllChars = oh.AddressOfEntryPoint, oh.ImageBase, oh.Subsystem, oh.DllCharacteristics
		dirs = oh.DataDirectory[:min(int(oh.NumberOfRvaAndSizes), 16)]
	default:
		add("pe-no-optional-header", "PE has no optional header", "Not a loadable image.", Medium)
	}
	dir := func(i int) pe.DataDirectory {
		if i < len(dirs) {
			return dirs[i]
		}
		return pe.DataDirectory{}
	}
	isDLL := f.Characteristics&pe.IMAGE_FILE_DLL != 0
	switch {
	case subsystem == pe.IMAGE_SUBSYSTEM_NATIVE:
		sl.Kind = "Windows driver / native image"
	case subsystem >= pe.IMAGE_SUBSYSTEM_EFI_APPLICATION && subsystem <= pe.IMAGE_SUBSYSTEM_EFI_ROM:
		sl.Kind = "EFI image"
	case isDLL:
		sl.Kind = "DLL"
	case subsystem == pe.IMAGE_SUBSYSTEM_WINDOWS_GUI:
		sl.Kind = "GUI executable"
	default:
		sl.Kind = "console executable"
	}
	sl.Entry = imageBase + uint64(entry)
	sl.Props["Image base"] = fmt.Sprintf("0x%x", imageBase)
	sl.Props["ASLR"] = yesNo(dllChars&pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0)
	sl.Props["DEP/NX"] = yesNo(dllChars&pe.IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0)
	sl.Props["Control Flow Guard"] = yesNo(dllChars&pe.IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0)
	if ts := f.TimeDateStamp; ts != 0 {
		t := time.Unix(int64(ts), 0).UTC()
		sl.Props["Compile timestamp"] = t.Format("2006-01-02 15:04 MST")
		if t.After(time.Now().Add(48 * time.Hour)) {
			add("pe-future-timestamp", "Compile timestamp is in the future", "Timestamps are often forged to hinder triage.", Low, t.Format(time.RFC3339))
		}
	}

	// Sections
	var lastEnd uint64
	var entrySect *pe.Section
	for i, s := range f.Sections {
		if s.Size > 0 && uint64(s.Offset)+uint64(s.Size) > lastEnd {
			lastEnd = uint64(s.Offset) + uint64(s.Size)
		}
		vsize := max(s.VirtualSize, s.Size)
		if entry >= s.VirtualAddress && entry < s.VirtualAddress+vsize {
			entrySect = f.Sections[i]
		}
		if i >= maxSections {
			continue
		}
		perms := permString(s.Characteristics&scnRead != 0, s.Characteristics&scnWrite != 0, s.Characteristics&scnExecute != 0)
		sec := Section{Name: s.Name, Offset: uint64(s.Offset), Size: uint64(s.Size), Addr: uint64(s.VirtualAddress), Perms: perms}
		if raw := sub(data, uint64(s.Offset), uint64(s.Size)); len(raw) > 0 {
			if sec.Entropy, err = bu.entropy(raw); err != nil {
				return nil, err
			}
		}
		sl.Sections = append(sl.Sections, sec)
		exec := s.Characteristics&(scnExecute|scnCode) != 0
		if exec && s.Characteristics&scnWrite != 0 {
			add("pe-wx-section", "Writable and executable section", "Self-modifying or unpacking code needs W+X memory; normal compilers never emit it.", Medium, s.Name)
		}
		if exec && s.Size == 0 && s.VirtualSize > 4096 {
			add("pe-empty-exec-section", "Executable section has no data on disk", "The code is written into this section at run time — typical of packers.", Medium,
				fmt.Sprintf("%s: virtual size %d", s.Name, s.VirtualSize))
		}
		if strings.HasPrefix(s.Name, "UPX") {
			add("packer-upx", "Packed with UPX", "UPX section names found.", Medium, s.Name)
		}
		if exec && sec.Entropy > 7.5 {
			add("packed-code", "Encrypted or compressed code section", "Machine code has entropy around 5–6.5 bits/byte; higher means it is packed or encrypted.", Medium,
				fmt.Sprintf("%s: %.2f bits/byte", s.Name, sec.Entropy))
		}
	}
	if entrySect != nil {
		sl.EntrySect = entrySect.Name
		if entrySect.Characteristics&(scnExecute|scnCode) == 0 {
			add("entry-non-exec", "Entry point in a non-executable section", "", High, entrySect.Name)
		} else if len(f.Sections) > 2 && entrySect == f.Sections[len(f.Sections)-1] {
			add("entry-last-section", "Entry point in the last section", "Packers and file infectors append their stub as the last section.", Medium, entrySect.Name)
		}
	} else if entry != 0 {
		add("entry-outside", "Entry point lies outside every section", "", High, fmt.Sprintf("RVA 0x%x", entry))
	}

	bu.finish(res, len(f.Sections))

	// Imports
	syms, anomaly, err := peImports(ctx, f, data)
	if err != nil {
		return nil, err
	}
	if anomaly != "" {
		add("pe-import-anomaly", "Import table exceeds sane limits", "Only part of the import table was read; tables this large are crafted to stall analysis tools.", Medium, anomaly)
	}
	libSeen := map[string]bool{}
	var imphash strings.Builder
	for _, s := range syms {
		fn, lib, _ := strings.Cut(s, ":")
		sl.Imports = append(sl.Imports, Import{Lib: lib, Name: fn})
		ll := strings.ToLower(lib)
		if !libSeen[ll] {
			libSeen[ll] = true
			sl.Libraries = append(sl.Libraries, lib)
		}
		base := ll
		for _, ext := range []string{".dll", ".ocx", ".sys"} {
			base = strings.TrimSuffix(base, ext)
		}
		if imphash.Len() > 0 {
			imphash.WriteByte(',')
		}
		imphash.WriteString(base + "." + strings.ToLower(fn))
	}
	tagImports(sl.Imports)
	if imphash.Len() > 0 {
		h := md5.Sum([]byte(imphash.String()))
		res.imphash = hex.EncodeToString(h[:])
	}
	res.dotnet = dir(14).Size > 0
	if res.dotnet {
		sl.Props[".NET"] = "yes (managed code — IL not analysed)"
	}
	if !res.dotnet && sl.Kind != "Windows driver / native image" && !strings.HasPrefix(sl.Kind, "EFI") {
		names := map[string]bool{}
		for _, im := range sl.Imports {
			names[normalizeAPI(im.Name)] = true
		}
		switch {
		case len(sl.Imports) == 0 && !isDLL:
			add("pe-no-imports", "No imported functions", "Real programs import from system DLLs; an empty import table means imports are resolved by hidden code.", Medium)
		case len(sl.Imports) <= 12 && (names["GetProcAddress"] || names["LdrGetProcedureAddress"]) && (names["LoadLibrary"] || names["LoadLibraryEx"] || names["LoadLibraryA"] || names["LoadLibraryW"] || names["LdrLoadDll"] || names["GetModuleHandle"] || names["GetModuleHandleA"] || names["GetModuleHandleW"]):
			add("pe-dynamic-imports", "Tiny import table resolved at run time", "Only LoadLibrary/GetProcAddress-style imports: the real API list is hidden, typical of packers and shellcode loaders.", Medium,
				fmt.Sprintf("%d imports", len(sl.Imports)))
		}
	}

	// Exports
	if d := dir(0); d.Size >= 40 {
		if off, ok := rvaToOffset(f, d.VirtualAddress); ok && off+40 <= uint64(len(data)) {
			sl.ExportCount = int(binary.LittleEndian.Uint32(data[off+24:]))
		}
	}

	// TLS callbacks run before the entry point; used for anti-debug tricks.
	if d := dir(9); d.Size > 0 {
		if off, ok := rvaToOffset(f, d.VirtualAddress); ok {
			var cbVA uint64
			if sl.Bits == 64 && off+32 <= uint64(len(data)) {
				cbVA = binary.LittleEndian.Uint64(data[off+24:])
			} else if off+16 <= uint64(len(data)) {
				cbVA = uint64(binary.LittleEndian.Uint32(data[off+12:]))
			}
			if cbVA > imageBase {
				if coff, ok := rvaToOffset(f, uint32(cbVA-imageBase)); ok && coff+8 <= uint64(len(data)) {
					first := uint64(binary.LittleEndian.Uint32(data[coff:]))
					if sl.Bits == 64 {
						first = binary.LittleEndian.Uint64(data[coff:])
					}
					if first != 0 {
						add("pe-tls-callbacks", "TLS callbacks", "Code that runs before the entry point — sometimes legitimate, often used to evade debuggers.", Low)
					}
				}
			}
		}
	}

	// Authenticode: the security directory holds a file offset, not an RVA.
	certOff, certLen := uint64(0), uint64(0)
	if d := dir(4); d.Size > 8 {
		certOff, certLen = uint64(d.VirtualAddress), uint64(d.Size)
		if blob := sub(data, certOff+8, certLen-8); len(blob) > 0 {
			res.sig.Present = true
			res.sig.Kind = "Authenticode"
			fillSigner(&res.sig, blob)
		}
	}
	if !res.sig.Present {
		add("pe-unsigned", "Not digitally signed", "Commercial Windows software is almost always Authenticode-signed.", Low)
	}

	// Overlay: bytes past the last section, excluding a trailing signature.
	if size := uint64(len(data)); lastEnd > 0 && lastEnd < size {
		ov := size - lastEnd
		if certLen > 0 && certOff >= lastEnd && certOff+certLen <= size {
			ov -= certLen
		}
		if ov > 0 {
			res.overlay = int64(ov)
			sl.Props["Overlay"] = fmt.Sprintf("%d bytes after last section", ov)
		}
	}
	res.slices = []Slice{sl}
	return res, nil
}

// peImports returns the same "name:dll" list as debug/pe's ImportedSymbols,
// which copies the whole import section once per descriptor and so goes
// quadratic on crafted tables. This walk reads the mapped file in place,
// bounds names and stops at maxImportDescs / maxImportThunks; anomaly says
// which limit was hit.
func peImports(ctx context.Context, f *pe.File, data []byte) (syms []string, anomaly string, err error) {
	var idd pe.DataDirectory
	pe64 := false
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if oh.NumberOfRvaAndSizes <= pe.IMAGE_DIRECTORY_ENTRY_IMPORT {
			return nil, "", nil
		}
		idd = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	case *pe.OptionalHeader64:
		if oh.NumberOfRvaAndSizes <= pe.IMAGE_DIRECTORY_ENTRY_IMPORT {
			return nil, "", nil
		}
		idd, pe64 = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT], true
	default:
		return nil, "", nil
	}
	var ds *pe.Section
	for _, s := range f.Sections {
		if s.Offset != 0 && s.VirtualAddress <= idd.VirtualAddress && idd.VirtualAddress-s.VirtualAddress < s.VirtualSize {
			ds = s
			break
		}
	}
	if ds == nil {
		return nil, "", nil
	}
	sec := sub(data, uint64(ds.Offset), uint64(ds.Size))
	if uint64(len(sec)) < uint64(ds.Size) {
		return nil, "", nil // debug/pe cannot read a truncated section either
	}
	name := func(off uint32) string {
		if uint64(off) >= uint64(len(sec)) {
			return ""
		}
		b := sec[off:min(uint64(off)+maxImportNameLen, uint64(len(sec)))]
		if n := bytes.IndexByte(b, 0); n >= 0 {
			return string(b[:n])
		}
		return ""
	}
	seek := idd.VirtualAddress - ds.VirtualAddress
	if seek >= uint32(len(sec)) {
		return nil, "", nil
	}
	thunks := 0
	for d, n := sec[seek:], 0; len(d) >= 20; d, n = d[20:], n+1 {
		oft, dllRVA := binary.LittleEndian.Uint32(d[0:]), binary.LittleEndian.Uint32(d[12:])
		if oft == 0 {
			break
		}
		if n == maxImportDescs {
			return syms, fmt.Sprintf("more than %d import descriptors", maxImportDescs), nil
		}
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		dll := name(dllRVA - ds.VirtualAddress)
		off := oft - ds.VirtualAddress
		if off >= uint32(len(sec)) {
			break
		}
		for t := sec[off:]; ; {
			var va uint64
			var ordinal bool
			if pe64 {
				if len(t) < 8 {
					break
				}
				va, t = binary.LittleEndian.Uint64(t), t[8:]
				ordinal = va&(1<<63) != 0
			} else {
				if len(t) <= 4 {
					break
				}
				va, t = uint64(binary.LittleEndian.Uint32(t)), t[4:]
				ordinal = va&(1<<31) != 0
			}
			if va == 0 {
				break
			}
			if thunks++; thunks > maxImportThunks {
				return syms, fmt.Sprintf("more than %d imported functions", maxImportThunks), nil
			}
			if !ordinal {
				syms = append(syms, name(uint32(va)-ds.VirtualAddress+2)+":"+dll)
			}
		}
	}
	return syms, "", nil
}

func rvaToOffset(f *pe.File, rva uint32) (uint64, bool) {
	for _, s := range f.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+max(s.VirtualSize, s.Size) {
			d := rva - s.VirtualAddress
			if d >= s.Size {
				return 0, false
			}
			return uint64(s.Offset) + uint64(d), true
		}
	}
	return 0, false
}

func sub(data []byte, off, n uint64) []byte {
	if off >= uint64(len(data)) {
		return nil
	}
	end := off + n
	if end > uint64(len(data)) || end < off {
		end = uint64(len(data))
	}
	return data[off:end]
}

func permString(r, w, x bool) string {
	b := []byte("---")
	if r {
		b[0] = 'r'
	}
	if w {
		b[1] = 'w'
	}
	if x {
		b[2] = 'x'
	}
	return string(b)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
