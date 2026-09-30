package analyze

import (
	"bytes"
	"debug/elf"
	"fmt"
	"strings"
)

var knownInterpreters = []string{
	"/lib/ld-linux", "/lib64/ld-linux", "/lib/ld-musl", "/lib/ld64.so", "/lib64/ld64.so", "/system/bin/linker",
	"/libexec/ld-elf.so", "/usr/libexec/ld.so", "/lib/ld.so", "/nix/store/", "/lib/ld-linux-aarch64", "/lib/ld-linux-armhf",
	"/usr/lib/ld.so", "/usr/lib/libc.so", "/lib/ld-uClibc", "/gnu/store/",
}

func analyzeELF(data []byte) (*formatResult, error) {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	res := &formatResult{}
	add := func(id, title, detail string, sev Severity, ev ...string) {
		res.findings = append(res.findings, Finding{ID: id, Title: title, Detail: detail, Severity: sev, Category: "structure", Evidence: ev})
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
	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_INTERP:
			if b := sub(data, p.Off, p.Filesz); len(b) > 0 {
				interp = string(bytes.TrimRight(b, "\x00"))
			}
		case elf.PT_DYNAMIC:
			hasDynamic = true
		case elf.PT_GNU_STACK:
			execStack = p.Flags&elf.PF_X != 0
		case elf.PT_LOAD:
			perms := permString(p.Flags&elf.PF_R != 0, p.Flags&elf.PF_W != 0, p.Flags&elf.PF_X != 0)
			seg := Section{Name: "LOAD", Offset: p.Off, Size: p.Filesz, Addr: p.Vaddr, Perms: perms}
			if b := sub(data, p.Off, p.Filesz); len(b) > 0 {
				seg.Entropy = entropyOf(b)
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
		sec := Section{Name: s.Name, Offset: s.Offset, Size: s.Size, Addr: s.Addr,
			Perms: permString(s.Flags&elf.SHF_ALLOC != 0, s.Flags&elf.SHF_WRITE != 0, s.Flags&elf.SHF_EXECINSTR != 0)}
		if s.Type != elf.SHT_NOBITS {
			if b := sub(data, s.Offset, s.Size); len(b) > 0 {
				sec.Entropy = entropyOf(b)
			}
		}
		sl.Sections = append(sl.Sections, sec)
		if s.Flags&elf.SHF_EXECINSTR != 0 && s.Addr <= f.Entry && f.Entry < s.Addr+s.Size {
			sl.EntrySect = s.Name
		}
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
	if hasDynamic {
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
	res.slices = []Slice{sl}
	return res, nil
}
