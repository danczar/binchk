package analyze

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
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

func analyzeMachO(data []byte, fat bool) (*formatResult, error) {
	res := &formatResult{}
	if !fat {
		f, err := macho.NewFile(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		machoSlice(f, data, res)
		return res, nil
	}
	ff, err := macho.NewFatFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer ff.Close()
	for _, a := range ff.Arches {
		machoSlice(a.File, sub(data, uint64(a.Offset), uint64(a.Size)), res)
	}
	return res, nil
}

func machoSlice(f *macho.File, data []byte, res *formatResult) {
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
	hasSig := false
	var dyldEnv []string
	for _, l := range f.Loads {
		raw := l.Raw()
		if seg, ok := l.(*macho.Segment); ok {
			perms := permString(seg.Prot&1 != 0, seg.Prot&2 != 0, seg.Prot&4 != 0)
			s := Section{Name: seg.Name, Offset: seg.Offset, Size: seg.Filesz, Addr: seg.Addr, Perms: perms}
			if seg.Filesz > 0 {
				s.Entropy = entropyOf(sub(data, seg.Offset, seg.Filesz))
			}
			sl.Segments = append(sl.Segments, s)
			switch seg.Name {
			case "__TEXT":
				textAddr = seg.Addr
			case "__PAGEZERO":
				hasPageZero = true
			}
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
			if len(raw) >= 16 {
				off, n := bo.Uint32(raw[8:]), bo.Uint32(raw[12:])
				if blob := sub(data, uint64(off), uint64(n)); len(blob) > 0 {
					hasSig = true
					ents := parseCodeSignature(blob, &sig)
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
		if s.Flags&0xff != 1 && s.Offset != 0 { // skip S_ZEROFILL
			sec.Entropy = entropyOf(sub(data, uint64(s.Offset), s.Size))
		}
		exec := s.Flags&0x80000400 != 0 // S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
		if exec {
			sec.Perms = "r-x"
		}
		sl.Sections = append(sl.Sections, sec)
		if sl.Entry != 0 && s.Addr <= sl.Entry && sl.Entry < s.Addr+s.Size {
			sl.EntrySect = sec.Name
		}
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
// and returns the embedded entitlements plist, if any.
func parseCodeSignature(b []byte, sig *Signature) (ents string) {
	be := binary.BigEndian
	sig.Present = true
	sig.Kind = "Apple code signature"
	if len(b) < 12 || be.Uint32(b) != 0xfade0cc0 {
		sig.Flags = append(sig.Flags, "malformed")
		return ""
	}
	count := be.Uint32(b[8:])
	cmsSigned := false
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
		case magic == 0xfade0c02 && typ == 0 && n >= 44: // primary CodeDirectory
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
		case magic == 0xfade7171:
			ents = string(blob[8:])
		case magic == 0xfade0b01 && n > 8:
			cmsSigned = true
			fillSigner(sig, blob[8:])
		}
	}
	if !cmsSigned {
		sig.AdHoc = true
	}
	return ents
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
