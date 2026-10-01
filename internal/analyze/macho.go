package analyze

import (
	"bytes"
	"context"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

const (
	lcCodeSignature  = 0x1d
	lcLoadWeakDylib  = 0x80000018
	lcReexportDylib  = 0x8000001f
	lcLazyLoadDylib  = 0x20
	lcLoadUpward     = 0x80000023
	lcMain           = 0x80000028
	lcBuildVersion   = 0x32
	lcVersionMinOSX  = 0x24
	lcEncryptionInfo = 0x21
	lcEncryption64   = 0x2c
	lcDyldEnv        = 0x27
	mhKextBundle     = 0xb
	mhDSYM           = 0xa
)

var csFlagNames = []struct {
	bit  uint32
	name string
}{
	{0x2, "adhoc"}, {0x4, "get-task-allow"}, {0x100, "hard"}, {0x200, "kill"}, {0x800, "restrict"},
	{0x1000, "enforcement"}, {0x2000, "library-validation"}, {0x10000, "runtime"}, {0x20000, "linker-signed"},
}

var riskyEntitlements = map[string]string{
	"com.apple.security.cs.disable-library-validation":         "loads unsigned / third-party libraries",
	"com.apple.security.cs.allow-dyld-environment-variables":   "honours DYLD_INSERT_LIBRARIES injection",
	"com.apple.security.cs.allow-unsigned-executable-memory":   "may execute unsigned memory",
	"com.apple.security.cs.disable-executable-page-protection": "disables executable page protection",
	"com.apple.security.get-task-allow":                        "other processes may attach to it (debug build)",
	"com.apple.security.cs.debugger":                           "acts as a debugger of other processes",
}

var platformNames = map[uint32]string{1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 6: "Mac Catalyst", 7: "iOS Simulator", 11: "visionOS"}

func analyzeMachO(ctx context.Context, data []byte, fat bool) (*formatResult, error) {
	res := &formatResult{}
	bu := newFmtBudget(ctx, len(data))
	crafted := func() {
		res.findings = append(res.findings, Finding{ID: "macho-table-anomaly", Title: "Symbol or relocation tables are crafted",
			Detail:   "Repeated symbol tables, a flood of load commands, relocations that describe more data than the file holds or symbol names that overlap heavily. Linkers never emit these; they stall analysis tools, so those tables were not read in full.",
			Severity: Medium, Category: "structure"})
	}
	if !fat {
		r, odd := machoHeaderReader(data)
		if odd {
			crafted()
		}
		f, err := macho.NewFile(r)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if err := machoSlice(bu, f, data, res); err != nil {
			return nil, err
		}
		bu.finish(res, max(len(f.Loads), len(f.Sections)))
		return res, nil
	}
	r, narch, odd := fatHeaderReader(data)
	if odd {
		crafted()
	}
	if narch > maxFatArches {
		res.findings = append(res.findings, Finding{ID: "macho-many-arches", Title: "Unusually many architectures in a universal binary",
			Detail:   fmt.Sprintf("Only the first %d were analysed.", maxFatArches),
			Severity: Low, Category: "structure", Evidence: []string{fmt.Sprintf("%d architectures", narch)}})
	}
	ff, err := macho.NewFatFile(r)
	if err != nil {
		return nil, err
	}
	defer ff.Close()
	most := 0
	for _, a := range ff.Arches {
		if err := machoSlice(bu, a.File, sub(data, uint64(a.Offset), uint64(a.Size)), res); err != nil {
			return nil, err
		}
		most = max(most, len(a.Loads), len(a.Sections))
	}
	bu.finish(res, most)
	return res, nil
}

// fatHeaderReader returns a reader over a universal binary for
// macho.NewFatFile that shows at most maxFatArches slices, each patched as
// machoHeaderReader does, and the slice count the header claimed. debug/macho
// parses every slice up front, so a header naming many slices (all perhaps
// the same bytes) multiplies the work.
func fatHeaderReader(data []byte) (r io.ReaderAt, narch uint32, crafted bool) {
	if len(data) < 8 {
		return bytes.NewReader(data), 0, false
	}
	be := binary.BigEndian
	narch = be.Uint32(data[4:])
	var ps []patch
	if narch > maxFatArches {
		ps = append(ps, patch{4, be.AppendUint32(nil, maxFatArches)})
	}
	for a := sub(data, 8, 20*uint64(min(narch, maxFatArches))); len(a) >= 20; a = a[20:] {
		off := uint64(be.Uint32(a[8:]))
		sp, odd := machoPatches(sub(data, off, uint64(be.Uint32(a[12:]))), int64(off))
		ps, crafted = append(ps, sp...), crafted || odd
	}
	return readerWith(data, ps), narch, crafted
}

// machoHeaderReader returns a reader over a thin Mach-O for macho.NewFile
// patched by machoPatches, and whether anything needed patching.
func machoHeaderReader(data []byte) (io.ReaderAt, bool) {
	ps, crafted := machoPatches(data, 0)
	return readerWith(data, ps), crafted
}

// machoPatches hides from debug/macho the parts of the thin Mach-O s (at
// base in the file) that it would otherwise turn into unbounded work: every
// LC_SYMTAB and LC_DYSYMTAB after the first (each one re-reads its tables),
// section relocations (read eagerly, never used here) and a string table
// whose names overlap so heavily that decoding them costs symbols × size,
// which is zeroed. crafted reports anything beyond relocations that fit the
// file, which object files legitimately carry.
func machoPatches(s []byte, base int64) (ps []patch, crafted bool) {
	if len(s) < 28 {
		return nil, false
	}
	var bo binary.ByteOrder = binary.LittleEndian
	magic := bo.Uint32(s)
	if magic != macho.Magic32 && magic != macho.Magic64 {
		bo, magic = binary.BigEndian, binary.BigEndian.Uint32(s)
		if magic != macho.Magic32 && magic != macho.Magic64 {
			return nil, false
		}
	}
	hdr, segCmd, segHdr, sectSize, nrelocAt, symSize := uint64(28), uint32(macho.LoadCmdSegment), 56, 68, 52, 12
	if magic == macho.Magic64 {
		hdr, segCmd, segHdr, sectSize, nrelocAt, symSize = 32, uint32(macho.LoadCmdSegment64), 72, 80, 60, 16
	}
	cmds := sub(s, hdr, uint64(bo.Uint32(s[20:])))
	var fixed []byte // copy of cmds, made on the first change
	zero := func(at uint64) {
		if fixed == nil {
			fixed = bytes.Clone(cmds)
		}
		bo.PutUint32(fixed[at:], 0)
	}
	haveSymtab, haveDysymtab := false, false
	var symtab []byte
	var relocs uint64
	// debug/macho allocates per load command and reads the whole command
	// area once per slice, so both are capped: keepN commands ending at
	// keepEnd are what fits in maxLoadCommands / maxLoadCmdBytes.
	ncmds, cmdBytes := bo.Uint32(s[16:]), uint64(bo.Uint32(s[20:]))
	keepN, keepEnd := uint32(0), uint64(0)
	for i, at := uint32(0), uint64(0); i < ncmds && at+8 <= uint64(len(cmds)); i++ {
		cmd, size := bo.Uint32(cmds[at:]), uint64(bo.Uint32(cmds[at+4:]))
		if size < 8 || size > uint64(len(cmds))-at {
			break
		}
		if i < maxLoadCommands && at+size <= maxLoadCmdBytes {
			keepN, keepEnd = i+1, at+size
		}
		switch {
		case cmd == uint32(macho.LoadCmdSymtab) && !haveSymtab:
			haveSymtab, symtab = true, cmds[at:at+size]
		case cmd == uint32(macho.LoadCmdDysymtab) && !haveDysymtab:
			haveDysymtab = true
		case cmd == uint32(macho.LoadCmdSymtab), cmd == uint32(macho.LoadCmdDysymtab):
			zero(at) // an unknown command, kept as raw bytes
			crafted = true
		case cmd == segCmd:
			for sect := at + uint64(segHdr); sect+uint64(sectSize) <= at+size; sect += uint64(sectSize) {
				if n := bo.Uint32(cmds[sect+uint64(nrelocAt):]); n != 0 {
					relocs += uint64(n)
					zero(sect + uint64(nrelocAt))
				}
			}
		}
		at += size
	}
	if 8*relocs > uint64(len(s)) {
		crafted = true
	}
	if ncmds > maxLoadCommands || cmdBytes > maxLoadCmdBytes {
		hdrFix := make([]byte, 8)
		bo.PutUint32(hdrFix, keepN)
		bo.PutUint32(hdrFix[4:], uint32(keepEnd))
		ps = append(ps, patch{base + 16, hdrFix})
		crafted = true
	}
	if fixed != nil {
		ps = append(ps, patch{base + int64(hdr), fixed})
	}
	if len(symtab) >= 24 {
		syms := sub(s, uint64(bo.Uint32(symtab[8:])), uint64(bo.Uint32(symtab[12:]))*uint64(symSize))
		stroff := uint64(bo.Uint32(symtab[16:]))
		tab := sub(s, stroff, uint64(bo.Uint32(symtab[20:])))
		if left := nameAllowance(len(tab)); !namesFit(tab, nameOffsets(syms, symSize, bo), &left) {
			ps = append(ps, patch{base + int64(stroff), make([]byte, len(tab))})
			crafted = true
		}
	}
	return ps, crafted
}

func machoSlice(bu *fmtBudget, f *macho.File, data []byte, res *formatResult) error {
	add := func(id, title, detail string, sev Severity, ev ...string) {
		res.findings = append(res.findings, Finding{ID: id, Title: title, Detail: detail, Severity: sev, Category: "structure", Evidence: ev})
	}
	bo := f.ByteOrder
	sl := Slice{Arch: machoArch(f), Props: map[string]string{}}
	if f.Magic == macho.Magic64 {
		sl.Bits = 64
	} else {
		sl.Bits = 32
	}
	switch f.Type {
	case macho.TypeExec:
		sl.Kind = "executable"
	case macho.TypeDylib:
		sl.Kind = "dynamic library"
	case macho.TypeBundle:
		sl.Kind = "bundle / plugin"
	case macho.TypeObj:
		sl.Kind = "object file"
	case mhDSYM:
		sl.Kind = "debug symbols (dSYM)"
	case mhKextBundle:
		sl.Kind = "kernel extension"
		add("macho-kext", "macOS kernel extension", "Kernel extensions run with full kernel privileges.", Medium)
	default:
		sl.Kind = fmt.Sprintf("type %d", f.Type)
	}

	var textAddr uint64
	hasPageZero := false
	var sig Signature
	hasSig, seenSig := false, false
	var dyldEnv []string
	for _, l := range f.Loads {
		raw := l.Raw()
		if seg, ok := l.(*macho.Segment); ok {
			switch seg.Name {
			case "__TEXT":
				textAddr = seg.Addr
			case "__PAGEZERO":
				hasPageZero = true
			}
			if len(sl.Segments) >= maxSections {
				continue
			}
			perms := permString(seg.Prot&1 != 0, seg.Prot&2 != 0, seg.Prot&4 != 0)
			s := Section{Name: seg.Name, Offset: seg.Offset, Size: seg.Filesz, Addr: seg.Addr, Perms: perms}
			if seg.Filesz > 0 {
				var err error
				if s.Entropy, err = bu.entropy(sub(data, seg.Offset, seg.Filesz)); err != nil {
					return err
				}
			}
			sl.Segments = append(sl.Segments, s)
			if seg.Prot&7 == 7 {
				add("macho-rwx-segment", "Segment is writable and executable", "", Medium, seg.Name)
			}
			continue
		}
		if len(raw) < 8 {
			continue
		}
		cmd := bo.Uint32(raw)
		switch cmd {
		case lcLoadWeakDylib, lcReexportDylib, lcLazyLoadDylib, lcLoadUpward:
			if len(raw) >= 12 {
				if off := bo.Uint32(raw[8:]); int(off) < len(raw) {
					name := cstr(raw[off:])
					sl.Libraries = append(sl.Libraries, name+" (weak)")
					checkDylibPath(name, add)
				}
			}
		case lcMain:
			if len(raw) >= 16 {
				sl.Entry = textAddr + bo.Uint64(raw[8:])
			}
		case lcBuildVersion:
			if len(raw) >= 20 {
				plat := platformNames[bo.Uint32(raw[8:])]
				if plat == "" {
					plat = fmt.Sprintf("platform %d", bo.Uint32(raw[8:]))
				}
				sl.Props["Platform"] = plat
				sl.Props["Min OS"] = version(bo.Uint32(raw[12:]))
				sl.Props["SDK"] = version(bo.Uint32(raw[16:]))
			}
		case lcVersionMinOSX:
			if len(raw) >= 16 {
				sl.Props["Min OS"] = version(bo.Uint32(raw[8:]))
			}
		case lcEncryptionInfo, lcEncryption64:
			if len(raw) >= 20 && bo.Uint32(raw[16:]) != 0 {
				sl.Props["Encrypted"] = "yes (FairPlay)"
			}
		case lcDyldEnv:
			if len(raw) >= 12 {
				if off := bo.Uint32(raw[8:]); int(off) < len(raw) {
					dyldEnv = append(dyldEnv, cstr(raw[off:]))
				}
			}
		case lcCodeSignature:
			// dyld and the kernel read only the first one.
			if len(raw) >= 16 && !seenSig {
				seenSig = true
				off, n := bo.Uint32(raw[8:]), bo.Uint32(raw[12:])
				if blob := sub(data, uint64(off), uint64(n)); len(blob) > 0 {
					hasSig = true
					ents, crafted := parseCodeSignature(blob, &sig)
					if crafted {
						add("macho-sig-anomaly", "Code signature index is crafted", "The signature holds far more or repeated entries than codesign writes; only the first of each kind was read.", Medium)
					}
					for k, why := range riskyEntitlements {
						if strings.Contains(ents, "<key>"+k+"</key>") {
							add("macho-entitlement", "Weakening entitlement", why, Low, k)
						}
					}
					// Apple's own binaries hold private entitlements by design;
					// a forged platform flag fails codesign verification.
					if !sig.Platform && strings.Contains(ents, "<key>com.apple.private.") {
						add("macho-private-entitlement", "Claims Apple-private entitlements", "Third-party code cannot legitimately hold private entitlements.", Medium)
					}
				}
			}
		}
	}
	// Evaluated after the loop: LC_CODE_SIGNATURE comes last, and Apple's
	// own binaries legitimately set dyld paths.
	for _, env := range dyldEnv {
		if strings.HasPrefix(env, "DYLD_INSERT_LIBRARIES") {
			add("macho-dyld-env", "Embedded dyld environment variable", "Injects a library into the process at launch.", High, env)
		} else if !sig.Platform {
			add("macho-dyld-env", "Embedded dyld environment variable", "", Low, env)
		}
	}
	if f.Type == macho.TypeExec && sl.Bits == 64 && !hasPageZero {
		add("macho-no-pagezero", "Missing __PAGEZERO segment", "Every normal 64-bit macOS executable maps a null page guard.", Low)
	}

	for _, s := range f.Sections {
		sec := Section{Name: s.Seg + "," + s.Name, Offset: uint64(s.Offset), Size: s.Size, Addr: s.Addr}
		if sl.Entry != 0 && s.Addr <= sl.Entry && sl.Entry < s.Addr+s.Size {
			sl.EntrySect = sec.Name
		}
		if len(sl.Sections) >= maxSections {
			continue
		}
		if s.Flags&0xff != 1 && s.Offset != 0 { // skip S_ZEROFILL
			var err error
			if sec.Entropy, err = bu.entropy(sub(data, uint64(s.Offset), s.Size)); err != nil {
				return err
			}
		}
		exec := s.Flags&0x80000400 != 0 // S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
		if exec {
			sec.Perms = "r-x"
		}
		sl.Sections = append(sl.Sections, sec)
		if exec && s.Size > 4096 && sec.Entropy > 7.5 {
			add("packed-code", "Encrypted or compressed code section", "", Medium, fmt.Sprintf("%s: %.2f bits/byte", sec.Name, sec.Entropy))
		}
	}

	libs, _ := f.ImportedLibraries()
	for _, l := range libs {
		checkDylibPath(l, add)
	}
	sl.Libraries = append(libs, sl.Libraries...)
	syms, _ := f.ImportedSymbols()
	for _, s := range syms {
		sl.Imports = append(sl.Imports, Import{Name: s})
	}
	tagImports(sl.Imports)
	if f.Symtab != nil {
		for _, s := range f.Symtab.Syms {
			if s.Type&0x0e == 0x0e && s.Type&0x01 != 0 { // N_SECT | N_EXT
				sl.ExportCount++
			}
		}
	}

	switch {
	case f.Type == macho.TypeObj || f.Type == mhDSYM:
	case !hasSig:
		add("macho-unsigned", "Not code-signed", "macOS refuses to run unsigned arm64 code, and legitimate Mac software is signed by an identified developer.", Medium)
	case sig.AdHoc:
		add("macho-adhoc", "Ad-hoc signature only", "Signed without a developer identity, so Gatekeeper cannot tie it to anyone. Normal for locally built tools; unusual for downloaded software.", Low)
	case !sig.Hardened && !sig.Platform && f.Type == macho.TypeExec:
		add("macho-no-hardened-runtime", "Hardened runtime not enabled", "Notarised apps must enable the hardened runtime.", Info)
	}
	if hasSig && !res.sig.Present {
		res.sig = sig
	}
	res.slices = append(res.slices, sl)
	return nil
}

func checkDylibPath(p string, add func(id, title, detail string, sev Severity, ev ...string)) {
	switch {
	case strings.HasPrefix(p, "/tmp/"), strings.HasPrefix(p, "/private/tmp/"), strings.HasPrefix(p, "/var/tmp/"),
		strings.HasPrefix(p, "/Users/Shared/"), strings.HasPrefix(p, "/private/var/folders/"):
		add("macho-dylib-writable", "Loads a library from a world-writable location", "", High, p)
	case !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "@"):
		add("macho-dylib-relative", "Loads a library by relative path", "Relative paths resolve against the current directory and can be hijacked.", Medium, p)
	}
}

// parseCodeSignature decodes an Apple code-signature SuperBlob (big-endian)
// and returns the embedded entitlements plist, if any. Only the first
// maxSigBlobs index entries and the first blob of each kind are decoded, so
// an index of repeated entries cannot multiply the work; crafted reports
// that either limit was hit.
func parseCodeSignature(b []byte, sig *Signature) (ents string, crafted bool) {
	be := binary.BigEndian
	sig.Present = true
	sig.Kind = "Apple code signature"
	if len(b) < 12 || be.Uint32(b) != 0xfade0cc0 {
		sig.Flags = append(sig.Flags, "malformed")
		return "", false
	}
	count := be.Uint32(b[8:])
	if count > maxSigBlobs {
		count, crafted = maxSigBlobs, true
	}
	cmsSigned, hasCD, hasEnts := false, false, false
	for i := uint32(0); i < count && int(12+8*i+8) <= len(b); i++ {
		typ := be.Uint32(b[12+8*i:])
		off := be.Uint32(b[16+8*i:])
		if int(off)+8 > len(b) {
			continue
		}
		blob := b[off:]
		magic, n := be.Uint32(blob), int(be.Uint32(blob[4:]))
		if n < 8 || n > len(blob) {
			continue
		}
		blob = blob[:n]
		switch {
		case magic == 0xfade0c02 && typ == 0 && n >= 44 && !hasCD: // primary CodeDirectory
			hasCD = true
			ver := be.Uint32(blob[8:])
			flags := be.Uint32(blob[12:])
			if id := be.Uint32(blob[20:]); int(id) < n {
				sig.Identifier = cstr(blob[id:])
			}
			if ver >= 0x20200 && n >= 52 {
				if t := be.Uint32(blob[48:]); t != 0 && int(t) < n {
					sig.TeamID = cstr(blob[t:])
				}
			}
			sig.AdHoc = flags&0x2 != 0 || flags&0x20000 != 0
			if blob[38] != 0 { // CodeDirectory.platform: Apple OS binary
				sig.Platform = true
				sig.Flags = append(sig.Flags, "platform-binary")
			}
			sig.Hardened = flags&0x10000 != 0
			for _, fl := range csFlagNames {
				if flags&fl.bit != 0 {
					sig.Flags = append(sig.Flags, fl.name)
				}
			}
		case magic == 0xfade7171 && !hasEnts:
			hasEnts = true
			ents = string(blob[8:])
		case magic == 0xfade0b01 && n > 8 && !cmsSigned:
			cmsSigned = true
			fillSigner(sig, blob[8:])
		}
	}
	if !cmsSigned {
		sig.AdHoc = true
	}
	return ents, crafted
}

func machoArch(f *macho.File) string {
	switch f.Cpu {
	case macho.CpuArm64:
		if f.SubCpu&0xff == 2 {
			return "arm64e"
		}
		return "arm64"
	case macho.CpuAmd64:
		return "x86-64"
	case macho.Cpu386:
		return "x86"
	}
	return strings.TrimPrefix(f.Cpu.String(), "Cpu")
}

func version(v uint32) string {
	return fmt.Sprintf("%d.%d.%d", v>>16, (v>>8)&0xff, v&0xff)
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
