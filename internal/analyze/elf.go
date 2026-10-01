package analyze

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

var knownInterpreters = []string{
	"/lib/ld-linux", "/lib64/ld-linux", "/lib/ld-musl", "/lib/ld64.so", "/lib64/ld64.so", "/system/bin/linker",
	"/libexec/ld-elf.so", "/usr/libexec/ld.so", "/lib/ld.so", "/nix/store/", "/lib/ld-linux-aarch64", "/lib/ld-linux-armhf",
	"/usr/lib/ld.so", "/usr/lib/libc.so", "/lib/ld-uClibc", "/gnu/store/",
}

func analyzeELF(ctx context.Context, data []byte) (*formatResult, error) {
	r, craftedNames := elfHeaderReader(data)
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	res := &formatResult{}
	bu := newFmtBudget(ctx, len(data))
	add := func(id, title, detail string, sev Severity, ev ...string) {
		res.findings = append(res.findings, Finding{ID: id, Title: title, Detail: detail, Severity: sev, Category: "structure", Evidence: ev})
	}
	crafted := func(what string) {
		add("elf-table-anomaly", "Crafted "+what, "Linkers never emit tables like these; they stall analysis tools, so they were not read in full.", Medium)
	}
	if craftedNames {
		crafted("section name table")
	}
	sl := Slice{
		Arch:  strings.TrimPrefix(f.Machine.String(), "EM_"),
		Entry: f.Entry,
		Props: map[string]string{"OS/ABI": strings.TrimPrefix(f.OSABI.String(), "ELFOSABI_")},
	}
	if f.Class == elf.ELFCLASS64 {
		sl.Bits = 64
	} else {
		sl.Bits = 32
	}

	var interp string
	var hasDynamic, execStack bool
	interps := 0
	for i, p := range f.Progs {
		if i%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		switch p.Type {
		case elf.PT_INTERP:
			// The kernel honours only the first, and only up to PATH_MAX.
			if interps++; interps > 1 {
				continue
			}
			if b := sub(data, p.Off, min(p.Filesz, maxInterpLen)); len(b) > 0 {
				interp = string(bytes.TrimRight(b, "\x00"))
			}
		case elf.PT_DYNAMIC:
			hasDynamic = true
		case elf.PT_GNU_STACK:
			execStack = p.Flags&elf.PF_X != 0
		case elf.PT_LOAD:
			if len(sl.Segments) >= maxSections {
				continue
			}
			perms := permString(p.Flags&elf.PF_R != 0, p.Flags&elf.PF_W != 0, p.Flags&elf.PF_X != 0)
			seg := Section{Name: "LOAD", Offset: p.Off, Size: p.Filesz, Addr: p.Vaddr, Perms: perms}
			if b := sub(data, p.Off, p.Filesz); len(b) > 0 {
				if seg.Entropy, err = bu.entropy(b); err != nil {
					return nil, err
				}
			}
			sl.Segments = append(sl.Segments, seg)
			if perms == "rwx" {
				add("elf-rwx-segment", "Loadable segment is writable and executable", "Normal toolchains separate code and data; RWX segments are typical of packers and hand-built payloads.", Medium,
					fmt.Sprintf("vaddr 0x%x", p.Vaddr))
			}
			if p.Flags&elf.PF_X != 0 && seg.Entropy > 7.5 && p.Filesz > 4096 {
				add("packed-code", "Encrypted or compressed code segment", "", Medium, fmt.Sprintf("vaddr 0x%x: %.2f bits/byte", p.Vaddr, seg.Entropy))
			}
		}
	}

	switch f.Type {
	case elf.ET_EXEC:
		sl.Kind = "executable"
	case elf.ET_DYN:
		if interp != "" {
			sl.Kind = "executable (PIE)"
		} else {
			sl.Kind = "shared library"
		}
	case elf.ET_REL:
		sl.Kind = "relocatable object"
		if f.Section(".modinfo") != nil {
			sl.Kind = "Linux kernel module"
			add("elf-kernel-module", "Linux kernel module", "Kernel modules run with full privileges; malicious ones are rootkits.", Medium)
		}
	case elf.ET_CORE:
		sl.Kind = "core dump"
	default:
		sl.Kind = f.Type.String()
	}

	if interp != "" {
		sl.Props["Interpreter"] = interp
		known := false
		for _, k := range knownInterpreters {
			if strings.HasPrefix(interp, k) {
				known = true
				break
			}
		}
		if !known {
			add("elf-odd-interpreter", "Unusual program interpreter", "The dynamic loader is what runs first; a non-standard one can hijack execution.", Medium, interp)
		}
	}
	if interps > 1 {
		add("elf-multiple-interp", "Several program interpreter headers", "Linkers emit one PT_INTERP; extra ones are crafted to confuse analysis tools.", Medium, fmt.Sprintf("%d PT_INTERP headers", interps))
	}
	if f.Type == elf.ET_EXEC || f.Type == elf.ET_DYN {
		sl.Props["Linking"] = map[bool]string{true: "dynamic", false: "static"}[hasDynamic || interp != ""]
	}
	if execStack {
		add("elf-exec-stack", "Executable stack", "Disables a basic exploit mitigation.", Low)
	}

	// Sections
	if len(f.Sections) <= 1 && f.Type != elf.ET_REL {
		add("elf-no-sections", "Section headers stripped", "Removing section headers breaks analysis tools; typical of packers such as UPX.", Medium)
	}
	hasSymtab := false
	for _, s := range f.Sections {
		if s.Type == elf.SHT_NULL {
			continue
		}
		if s.Type == elf.SHT_SYMTAB {
			hasSymtab = true
		}
		if s.Flags&elf.SHF_EXECINSTR != 0 && s.Addr <= f.Entry && f.Entry < s.Addr+s.Size {
			sl.EntrySect = s.Name
		}
		if len(sl.Sections) >= maxSections {
			continue
		}
		sec := Section{Name: s.Name, Offset: s.Offset, Size: s.Size, Addr: s.Addr,
			Perms: permString(s.Flags&elf.SHF_ALLOC != 0, s.Flags&elf.SHF_WRITE != 0, s.Flags&elf.SHF_EXECINSTR != 0)}
		if s.Type != elf.SHT_NOBITS {
			if b := sub(data, s.Offset, s.Size); len(b) > 0 {
				if sec.Entropy, err = bu.entropy(b); err != nil {
					return nil, err
				}
			}
		}
		sl.Sections = append(sl.Sections, sec)
	}
	sl.Props["Symbols"] = map[bool]string{true: "present", false: "stripped"}[hasSymtab]
	if f.Entry != 0 && f.Type != elf.ET_REL {
		inExec := false
		for _, p := range f.Progs {
			if p.Type == elf.PT_LOAD && f.Entry >= p.Vaddr && f.Entry < p.Vaddr+p.Memsz {
				inExec = p.Flags&elf.PF_X != 0
				break
			}
		}
		if !inExec {
			add("entry-non-exec", "Entry point not in an executable segment", "", High, fmt.Sprintf("0x%x", f.Entry))
		}
	}

	// Dynamic linking info
	if hasDynamic && !elfDynamicFits(f, data) {
		crafted("dynamic symbol or version tables")
	} else if hasDynamic {
		libs, _ := f.ImportedLibraries()
		sl.Libraries = libs
		syms, _ := f.ImportedSymbols()
		for _, s := range syms {
			sl.Imports = append(sl.Imports, Import{Lib: s.Library, Name: s.Name})
		}
		tagImports(sl.Imports)
		if dsyms, err := f.DynamicSymbols(); err == nil {
			for _, s := range dsyms {
				if s.Section != elf.SHN_UNDEF && elf.ST_BIND(s.Info) == elf.STB_GLOBAL {
					sl.ExportCount++
				}
			}
		}
		for _, tag := range []elf.DynTag{elf.DT_RPATH, elf.DT_RUNPATH} {
			paths, _ := f.DynString(tag)
			for _, p := range paths {
				sl.Props[strings.TrimPrefix(tag.String(), "DT_")] = p
				for _, e := range strings.Split(p, ":") {
					if e == "" || e == "." || (!strings.HasPrefix(e, "/") && !strings.HasPrefix(e, "$ORIGIN")) ||
						strings.HasPrefix(e, "/tmp") || strings.HasPrefix(e, "/dev/shm") || strings.HasPrefix(e, "/var/tmp") {
						add("elf-bad-rpath", "Library search path is relative or world-writable", "Lets an attacker plant a library that this program will load.", Medium, e)
					}
				}
			}
		}
	}
	bu.finish(res, max(len(f.Progs), len(f.Sections)))
	res.slices = []Slice{sl}
	return res, nil
}

// elfHeaderReader returns a reader over data for elf.NewFile, and whether
// the section name table needed patching: elf.NewFile decompresses it if
// flagged compressed (a decompression bomb) and copies one name per section
// header, so names overlapping one long run cost headers × size. A
// compressed table is read raw instead and an overlapping one is zeroed.
func elfHeaderReader(data []byte) (io.ReaderAt, bool) {
	if len(data) < 64 || data[4] != byte(elf.ELFCLASS32) && data[4] != byte(elf.ELFCLASS64) {
		return bytes.NewReader(data), false
	}
	var bo binary.ByteOrder = binary.LittleEndian
	if data[5] == byte(elf.ELFDATA2MSB) {
		bo = binary.BigEndian
	}
	is64 := data[4] == byte(elf.ELFCLASS64)
	shoff, shentsize, shnum, shstrndx := uint64(bo.Uint32(data[0x20:])), uint64(bo.Uint16(data[0x2e:])), uint64(bo.Uint16(data[0x30:])), uint64(bo.Uint16(data[0x32:]))
	// Field offsets within a section header: flags, offset, size, link.
	flagsAt, offAt, sizeAt, linkAt := uint64(8), uint64(16), uint64(20), uint64(24)
	if is64 {
		shoff, shentsize, shnum, shstrndx = bo.Uint64(data[0x28:]), uint64(bo.Uint16(data[0x3a:])), uint64(bo.Uint16(data[0x3c:])), uint64(bo.Uint16(data[0x3e:]))
		flagsAt, offAt, sizeAt, linkAt = 8, 24, 32, 40
	}
	if shoff == 0 || shentsize < linkAt+4 {
		return bytes.NewReader(data), false
	}
	word := func(b []byte) uint64 {
		if is64 {
			return bo.Uint64(b)
		}
		return uint64(bo.Uint32(b))
	}
	if sh0 := sub(data, shoff, shentsize); uint64(len(sh0)) == shentsize {
		if shnum == 0 { // extended numbering
			shnum = word(sh0[sizeAt:])
		}
		if shstrndx == uint64(elf.SHN_XINDEX) {
			shstrndx = uint64(bo.Uint32(sh0[linkAt:]))
		}
	}
	if shstrndx == 0 || shstrndx >= shnum || shnum > uint64(len(data))/shentsize {
		return bytes.NewReader(data), false
	}
	shdrs := sub(data, shoff, shnum*shentsize)
	if uint64(len(shdrs)) < shnum*shentsize {
		return bytes.NewReader(data), false
	}
	var ps []patch
	crafted := false
	sh := shdrs[shstrndx*shentsize:][:shentsize]
	if word(sh[flagsAt:])&uint64(elf.SHF_COMPRESSED) != 0 {
		fixed := bytes.Clone(sh)
		if is64 {
			bo.PutUint64(fixed[flagsAt:], word(sh[flagsAt:])&^uint64(elf.SHF_COMPRESSED))
		} else {
			bo.PutUint32(fixed[flagsAt:], uint32(word(sh[flagsAt:])&^uint64(elf.SHF_COMPRESSED)))
		}
		ps, crafted = append(ps, patch{int64(shoff + shstrndx*shentsize), fixed}), true
	}
	tab := sub(data, word(sh[offAt:]), word(sh[sizeAt:]))
	if left := nameAllowance(len(tab)); !namesFit(tab, nameOffsets(shdrs, int(shentsize), bo), &left) {
		ps, crafted = append(ps, patch{int64(word(sh[offAt:])), make([]byte, len(tab))}), true
	}
	return readerWith(data, ps), crafted
}

// elfDynamicFits reports whether debug/elf's dynamic symbol, dynamic string
// and symbol version lookups stay roughly linear in the file size. Their
// names can all point into one long run, the version tables are linked lists
// whose entries may overlap, and every symbol scans every version; the
// tables may also be compressed (SHF_COMPRESSED, or a legacy ".zdebug" name
// with a ZLIB header), which no loader accepts and which turns them into
// decompression bombs whose cost the raw bytes do not show.
func elfDynamicFits(f *elf.File, data []byte) bool {
	bo := f.ByteOrder
	is64 := f.Class == elf.ELFCLASS64
	// view returns the bytes debug/elf reads for s, which must be exactly
	// the raw file bytes: any decompression path debug/elf takes, now or in
	// a later release, shows up as a difference. Reading stops one byte past
	// the raw size, so a bomb costs no more than the bytes it occupies.
	fits := true
	view := func(s *elf.Section) []byte {
		if s == nil || s.Type == elf.SHT_NOBITS {
			return nil
		}
		b := sub(data, s.Offset, s.FileSize)
		got, err := io.ReadAll(io.LimitReader(s.Open(), int64(len(b))+1))
		if err != nil || !bytes.Equal(got, b) {
			fits = false
		}
		return b
	}
	link := func(s *elf.Section) *elf.Section {
		if s == nil || s.Link == 0 || int(s.Link) >= len(f.Sections) {
			return nil
		}
		return f.Sections[s.Link]
	}
	dynsym, dyn := f.SectionByType(elf.SHT_DYNSYM), f.SectionByType(elf.SHT_DYNAMIC)
	syms, dynstr := view(dynsym), view(link(dynsym))
	dynb, dyntab := view(dyn), view(link(dyn))
	verdef, verneed := view(f.SectionByType(elf.SHT_GNU_VERDEF)), view(f.SectionByType(elf.SHT_GNU_VERNEED))
	versym := f.SectionByType(elf.SHT_GNU_VERSYM)
	view(versym)
	if !fits {
		return false
	}
	left := nameAllowance(len(data))
	name := func(tab []byte, off uint64) bool {
		return namesFit(tab, func(yield func(uint64) bool) { yield(off) }, &left)
	}

	// ImportedSymbols and DynamicSymbols each decode every name.
	stride := map[bool]int{false: 16, true: 24}[is64]
	nsyms := uint64(len(syms) / stride)
	for range 2 {
		if !namesFit(dynstr, nameOffsets(syms, stride, bo), &left) {
			return false
		}
	}

	stride = map[bool]int{false: 8, true: 16}[is64]
	for b := dynb; len(b) >= stride; b = b[stride:] {
		tag, val := elf.DynTag(int32(bo.Uint32(b))), uint64(bo.Uint32(b[4:]))
		if is64 {
			tag, val = elf.DynTag(int64(bo.Uint64(b))), bo.Uint64(b[8:])
		}
		switch tag {
		case elf.DT_NEEDED, elf.DT_SONAME, elf.DT_RPATH, elf.DT_RUNPATH:
			if !name(dyntab, val) {
				return false
			}
		}
	}

	// Walk the version tables as debug/elf does (twice: neither call caches
	// an empty result), counting entries.
	versions := uint64(0)
	walk := func(d []byte, recSize, auxSize uint64, needs bool) bool {
		for i := uint64(0); i+recSize <= uint64(len(d)); {
			if bo.Uint16(d[i:]) != 1 {
				return true // debug/elf stops with an error
			}
			var cnt, aux, next uint64
			if needs {
				cnt, aux, next = uint64(bo.Uint16(d[i+2:])), uint64(bo.Uint32(d[i+8:])), uint64(bo.Uint32(d[i+12:]))
				if !name(dynstr, uint64(bo.Uint32(d[i+4:]))) {
					return false
				}
			} else if cnt, aux, next = uint64(bo.Uint16(d[i+6:])), uint64(bo.Uint32(d[i+12:])), uint64(bo.Uint32(d[i+16:])); cnt == 0 {
				return true
			}
			for j, c := i+aux, uint64(0); c < cnt && j+auxSize <= uint64(len(d)); c++ {
				nameAt, nextAt := j, j+4
				if needs {
					nameAt, nextAt = j+8, j+12
				}
				if versions++; versions > maxVersionEntries || !name(dynstr, uint64(bo.Uint32(d[nameAt:]))) {
					return false
				}
				vnext := uint64(bo.Uint32(d[nextAt:]))
				if vnext == 0 {
					break
				}
				j += vnext
			}
			if versions++; versions > maxVersionEntries || next == 0 {
				return versions <= maxVersionEntries
			}
			i += next
		}
		return true
	}
	if versym != nil {
		for range 2 {
			if !walk(verdef, 20, 8, false) || !walk(verneed, 16, 16, true) {
				return false
			}
		}
	}
	// Each symbol's version lookup scans every version entry, in both calls.
	return versions == 0 || 2*nsyms <= left/versions
}
