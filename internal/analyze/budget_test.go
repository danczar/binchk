package analyze

import (
	"bytes"
	"compress/zlib"
	"context"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"
)

// overlapELF builds a valid ELF64 whose n PROGBITS section headers all cover
// the same dataLen bytes, so naive per-section entropy costs n*dataLen.
func overlapELF(n, dataLen int) []byte {
	const ehsize, shentsize = 64, 64
	shoff := ehsize + dataLen
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, elf.Header64{
		Ident:     [16]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)},
		Type:      uint16(elf.ET_EXEC),
		Machine:   uint16(elf.EM_X86_64),
		Version:   uint32(elf.EV_CURRENT),
		Shoff:     uint64(shoff),
		Ehsize:    ehsize,
		Shentsize: shentsize,
		Shnum:     uint16(n + 1),
	})
	data := make([]byte, dataLen)
	for i := range data {
		data[i] = byte(i * 7)
	}
	b.Write(data)
	binary.Write(&b, binary.LittleEndian, elf.Section64{}) // SHT_NULL
	for range n {
		binary.Write(&b, binary.LittleEndian, elf.Section64{Type: uint32(elf.SHT_PROGBITS), Off: ehsize, Size: uint64(dataLen)})
	}
	return b.Bytes()
}

// manyDescriptorPE builds a PE32+ whose import section of secLen bytes is
// packed with n import descriptors; debug/pe copies the whole section once
// per descriptor.
func manyDescriptorPE(n, secLen int) []byte {
	const secOff, secVA = 0x400, 0x1000
	var b bytes.Buffer
	dos := make([]byte, 0x40)
	copy(dos, "MZ")
	binary.LittleEndian.PutUint32(dos[0x3c:], 0x40)
	b.Write(dos)
	b.WriteString("PE\x00\x00")
	binary.Write(&b, binary.LittleEndian, pe.FileHeader{Machine: pe.IMAGE_FILE_MACHINE_AMD64, NumberOfSections: 1,
		SizeOfOptionalHeader: 240, Characteristics: pe.IMAGE_FILE_EXECUTABLE_IMAGE | pe.IMAGE_FILE_LARGE_ADDRESS_AWARE})
	oh := pe.OptionalHeader64{Magic: 0x20b, AddressOfEntryPoint: secVA, ImageBase: 0x140000000, SectionAlignment: 0x1000,
		FileAlignment: 0x200, SizeOfImage: uint32(secVA + secLen), SizeOfHeaders: secOff, Subsystem: pe.IMAGE_SUBSYSTEM_WINDOWS_CUI,
		NumberOfRvaAndSizes: 16}
	oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT] = pe.DataDirectory{VirtualAddress: secVA, Size: uint32(20 * n)}
	binary.Write(&b, binary.LittleEndian, oh)
	sh := pe.SectionHeader32{VirtualSize: uint32(secLen), VirtualAddress: secVA, SizeOfRawData: uint32(secLen),
		PointerToRawData: secOff, Characteristics: scnRead | scnExecute | scnCode}
	copy(sh.Name[:], ".idata")
	binary.Write(&b, binary.LittleEndian, sh)
	b.Write(make([]byte, secOff-b.Len()))

	sec := make([]byte, secLen)
	// Tail: a DLL name, a hint/name entry and a one-entry thunk array.
	nameOff, hintOff, thunkOff := secLen-64, secLen-48, secLen-16
	copy(sec[nameOff:], "a.dll\x00")
	copy(sec[hintOff+2:], "f\x00")
	binary.LittleEndian.PutUint64(sec[thunkOff:], uint64(secVA+hintOff))
	for i := range n {
		d := sec[20*i:]
		binary.LittleEndian.PutUint32(d[0:], uint32(secVA+thunkOff))
		binary.LittleEndian.PutUint32(d[12:], uint32(secVA+nameOff))
		binary.LittleEndian.PutUint32(d[16:], uint32(secVA+thunkOff))
	}
	b.Write(sec)
	return b.Bytes()
}

// sigBlobMachO builds a thin arm64 executable whose code-signature
// SuperBlob has n index entries that all name one entsLen-byte entitlements
// blob, so parsing each entry costs n*entsLen.
func sigBlobMachO(n, entsLen int) []byte {
	be := binary.BigEndian
	const sigOff = 4096
	ents := 12 + 8*n
	sig := make([]byte, ents+8+entsLen)
	be.PutUint32(sig[0:], 0xfade0cc0)
	be.PutUint32(sig[4:], uint32(len(sig)))
	be.PutUint32(sig[8:], uint32(n))
	for i := range n {
		be.PutUint32(sig[12+8*i:], 5)
		be.PutUint32(sig[16+8*i:], uint32(ents))
	}
	be.PutUint32(sig[ents:], 0xfade7171)
	be.PutUint32(sig[ents+4:], uint32(8+entsLen))
	copy(sig[ents+8:], bytes.Repeat([]byte("a"), entsLen))

	b := make([]byte, sigOff, sigOff+len(sig))
	le := binary.LittleEndian
	le.PutUint32(b[0:], macho.Magic64)
	le.PutUint32(b[4:], uint32(macho.CpuArm64))
	le.PutUint32(b[12:], uint32(macho.TypeExec))
	le.PutUint32(b[16:], 1)  // ncmds
	le.PutUint32(b[20:], 16) // sizeofcmds
	le.PutUint32(b[32:], lcCodeSignature)
	le.PutUint32(b[36:], 16)
	le.PutUint32(b[40:], sigOff)
	le.PutUint32(b[44:], uint32(len(sig)))
	return append(b, sig...)
}

// fatArchesMachO builds a fat file with n arches (distinct subtypes) that all
// point at one thin slice carrying ncmds load commands.
func fatArchesMachO(n, ncmds int) []byte {
	const cmdSize = 24 // LC_UUID
	thin := make([]byte, 32+cmdSize*ncmds)
	le := binary.LittleEndian
	le.PutUint32(thin[0:], macho.Magic64)
	le.PutUint32(thin[4:], uint32(macho.CpuArm64))
	le.PutUint32(thin[12:], uint32(macho.TypeExec))
	le.PutUint32(thin[16:], uint32(ncmds))
	le.PutUint32(thin[20:], uint32(cmdSize*ncmds))
	for i := range ncmds {
		le.PutUint32(thin[32+cmdSize*i:], 0x1b)
		le.PutUint32(thin[36+cmdSize*i:], cmdSize)
	}
	be := binary.BigEndian
	off := (8 + 20*n + 0x3fff) &^ 0x3fff
	b := make([]byte, off, off+len(thin))
	be.PutUint32(b[0:], macho.MagicFat)
	be.PutUint32(b[4:], uint32(n))
	for i := range n {
		a := b[8+20*i:]
		be.PutUint32(a[0:], uint32(macho.CpuArm64))
		be.PutUint32(a[4:], uint32(i))
		be.PutUint32(a[8:], uint32(off))
		be.PutUint32(a[12:], uint32(len(thin)))
		be.PutUint32(a[16:], 14)
	}
	return append(b, thin...)
}

// relocPE builds a PE32+ with n section headers that each claim 65535 COFF
// relocations at the same offset; debug/pe reads them all eagerly.
func relocPE(n int) []byte {
	var b bytes.Buffer
	dos := make([]byte, 0x40)
	copy(dos, "MZ")
	binary.LittleEndian.PutUint32(dos[0x3c:], 0x40)
	b.Write(dos)
	b.WriteString("PE\x00\x00")
	binary.Write(&b, binary.LittleEndian, pe.FileHeader{Machine: pe.IMAGE_FILE_MACHINE_AMD64, NumberOfSections: uint16(n),
		SizeOfOptionalHeader: 240, Characteristics: pe.IMAGE_FILE_EXECUTABLE_IMAGE | pe.IMAGE_FILE_LARGE_ADDRESS_AWARE})
	relocOff := 0x40 + 4 + 20 + 240 + 40*n
	binary.Write(&b, binary.LittleEndian, pe.OptionalHeader64{Magic: 0x20b, ImageBase: 0x140000000, SectionAlignment: 0x1000,
		FileAlignment: 0x200, SizeOfHeaders: uint32(relocOff), NumberOfRvaAndSizes: 16})
	for range n {
		binary.Write(&b, binary.LittleEndian, pe.SectionHeader32{PointerToRelocations: uint32(relocOff), NumberOfRelocations: 65535})
	}
	b.Write(make([]byte, 10*65535))
	return b.Bytes()
}

// interpELF builds an ELF64 whose n program headers are all PT_INTERP over
// the same dataLen bytes.
func interpELF(n, dataLen int) []byte {
	const ehsize, phentsize = 64, 56
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, elf.Header64{
		Ident:     [16]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)},
		Type:      uint16(elf.ET_EXEC),
		Machine:   uint16(elf.EM_X86_64),
		Version:   uint32(elf.EV_CURRENT),
		Phoff:     uint64(ehsize + dataLen),
		Ehsize:    ehsize,
		Phentsize: phentsize,
		Phnum:     uint16(n),
	})
	b.Write(bytes.Repeat([]byte("x"), dataLen))
	for range n {
		binary.Write(&b, binary.LittleEndian, elf.Prog64{Type: uint32(elf.PT_INTERP), Off: ehsize, Filesz: uint64(dataLen)})
	}
	return b.Bytes()
}

// symtabMachO builds a thin arm64 executable with cmds LC_SYMTAB commands
// sharing one table of nsyms symbols, all named by the strLen-byte run at
// offset 1 of the string table; debug/macho copies each name and re-reads
// the tables per command.
func symtabMachO(cmds, nsyms, strLen int) []byte {
	le := binary.LittleEndian
	symoff := 32 + 24*cmds
	stroff := symoff + 16*nsyms
	b := make([]byte, stroff+strLen+1)
	le.PutUint32(b[0:], macho.Magic64)
	le.PutUint32(b[4:], uint32(macho.CpuArm64))
	le.PutUint32(b[12:], uint32(macho.TypeExec))
	le.PutUint32(b[16:], uint32(cmds))
	le.PutUint32(b[20:], uint32(24*cmds))
	for i := range cmds {
		c := b[32+24*i:]
		le.PutUint32(c[0:], uint32(macho.LoadCmdSymtab))
		le.PutUint32(c[4:], 24)
		le.PutUint32(c[8:], uint32(symoff))
		le.PutUint32(c[12:], uint32(nsyms))
		le.PutUint32(c[16:], uint32(stroff))
		le.PutUint32(c[20:], uint32(strLen+1))
	}
	for i := range nsyms {
		le.PutUint32(b[symoff+16*i:], 1)
	}
	copy(b[stroff+1:], bytes.Repeat([]byte("a"), strLen-1))
	return b
}

// elfWith lays out an ELF64 with one PT_DYNAMIC program header and the given
// sections (data plus header template) after it; the section name table is
// the last section when names is non-nil.
func elfWith(secs []elf.Section64, data [][]byte, names []uint32) []byte {
	var body bytes.Buffer
	const start = 64 + 56
	for i := range secs {
		secs[i].Off, secs[i].Size = uint64(start+body.Len()), uint64(len(data[i]))
		body.Write(data[i])
	}
	shoff := start + body.Len()
	var b bytes.Buffer
	h := elf.Header64{
		Ident:     [16]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)},
		Type:      uint16(elf.ET_DYN),
		Machine:   uint16(elf.EM_X86_64),
		Version:   uint32(elf.EV_CURRENT),
		Phoff:     64,
		Shoff:     uint64(shoff),
		Ehsize:    64,
		Phentsize: 56,
		Phnum:     1,
		Shentsize: 64,
		Shnum:     uint16(len(secs) + 1 + len(names)),
	}
	if names != nil {
		h.Shnum, h.Shstrndx = uint16(len(names)), uint16(len(names)-1)
	}
	binary.Write(&b, binary.LittleEndian, h)
	binary.Write(&b, binary.LittleEndian, elf.Prog64{Type: uint32(elf.PT_DYNAMIC), Flags: uint32(elf.PF_R)})
	b.Write(body.Bytes())
	if names != nil {
		// Every header but the last (the name table itself) names offset 1.
		for i, n := range names[:len(names)-1] {
			binary.Write(&b, binary.LittleEndian, elf.Section64{Name: n, Type: uint32(elf.SHT_PROGBITS), Off: uint64(start), Size: uint64(min(i, 1))})
		}
		binary.Write(&b, binary.LittleEndian, elf.Section64{Type: uint32(elf.SHT_STRTAB), Off: secs[0].Off, Size: secs[0].Size})
		return b.Bytes()
	}
	binary.Write(&b, binary.LittleEndian, elf.Section64{})
	for _, s := range secs {
		binary.Write(&b, binary.LittleEndian, s)
	}
	return b.Bytes()
}

// strtab is a string table whose name at offset 1 runs n bytes.
func strtab(n int) []byte {
	return append(append([]byte{0}, bytes.Repeat([]byte("a"), n)...), 0)
}

// shnamesELF has n section headers all named by one long run.
func shnamesELF(n, strLen int) []byte {
	names := make([]uint32, n)
	for i := range names {
		names[i] = 1
	}
	return elfWith([]elf.Section64{{}}, [][]byte{strtab(strLen)}, names)
}

// dynELF has a dynamic symbol table of nsyms symbols all named by one
// strLen-byte run, and a version-needs table of recs overlapping records
// that debug/elf walks recs² times.
func dynELF(nsyms, strLen, recs int) []byte {
	le := binary.LittleEndian
	syms := make([]byte, 24*(nsyms+1))
	for i := 1; i <= nsyms; i++ {
		le.PutUint32(syms[24*i:], 1)
		syms[24*i+4] = byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC)
	}
	// Each record doubles as the aux entry of the one before: version 1,
	// 65535 aux entries, aux and next both one record on.
	rec := []byte{1, 0, 0xff, 0xff, 0, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0}
	return elfWith([]elf.Section64{
		{Type: uint32(elf.SHT_DYNSYM), Link: 2, Entsize: 24},
		{Type: uint32(elf.SHT_STRTAB)},
		{Type: uint32(elf.SHT_GNU_VERSYM), Link: 1},
		{Type: uint32(elf.SHT_GNU_VERNEED), Link: 2},
	}, [][]byte{syms, strtab(strLen), make([]byte, 2*(nsyms+1)), bytes.Repeat(rec, recs)}, nil)
}

// namedELF lays out an ELF64 ET_DYN with one PT_DYNAMIC program header and
// the given named sections, followed by a section name table.
func namedELF(secs []elf.Section64, data [][]byte, names []string) []byte {
	shstr := []byte{0}
	for i, n := range names {
		secs[i].Name = uint32(len(shstr))
		shstr = append(append(shstr, n...), 0)
	}
	nameOff := uint32(len(shstr))
	shstr = append(shstr, ".shstrtab\x00"...)
	secs = append(secs, elf.Section64{Name: nameOff, Type: uint32(elf.SHT_STRTAB)})
	data = append(data, shstr)
	var body bytes.Buffer
	const start = 64 + 56
	for i := range secs {
		secs[i].Off, secs[i].Size = uint64(start+body.Len()), uint64(len(data[i]))
		body.Write(data[i])
	}
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, elf.Header64{
		Ident:     [16]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)},
		Type:      uint16(elf.ET_DYN),
		Machine:   uint16(elf.EM_X86_64),
		Version:   uint32(elf.EV_CURRENT),
		Phoff:     64,
		Shoff:     uint64(start + body.Len()),
		Ehsize:    64,
		Phentsize: 56,
		Phnum:     1,
		Shentsize: 64,
		Shnum:     uint16(len(secs) + 1),
		Shstrndx:  uint16(len(secs)),
	})
	binary.Write(&b, binary.LittleEndian, elf.Prog64{Type: uint32(elf.PT_DYNAMIC), Flags: uint32(elf.PF_R)})
	b.Write(body.Bytes())
	binary.Write(&b, binary.LittleEndian, elf.Section64{})
	for _, s := range secs {
		binary.Write(&b, binary.LittleEndian, s)
	}
	return b.Bytes()
}

// zdebug wraps b the way debug/elf decompresses any section named
// ".zdebug*", whatever its flags say.
func zdebug(b []byte) []byte {
	var z bytes.Buffer
	z.WriteString("ZLIB")
	binary.Write(&z, binary.BigEndian, uint64(len(b)))
	w, _ := zlib.NewWriterLevel(&z, zlib.BestCompression)
	w.Write(b)
	w.Close()
	return z.Bytes()
}

// zdebugSymsELF hides a dynamic symbol table of nsyms symbols, all named by
// one strLen-byte run, behind a legacy ".zdebug" ZLIB header, so the raw
// bytes are tiny while debug/elf copies nsyms × strLen bytes of names.
func zdebugSymsELF(nsyms, strLen int) []byte {
	syms := make([]byte, 24*(nsyms+1))
	for i := 1; i <= nsyms; i++ {
		binary.LittleEndian.PutUint32(syms[24*i:], 1)
		syms[24*i+4] = byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC)
	}
	return namedELF([]elf.Section64{
		{Type: uint32(elf.SHT_DYNSYM), Link: 2, Entsize: 24},
		{Type: uint32(elf.SHT_STRTAB)},
	}, [][]byte{zdebug(syms), strtab(strLen)}, []string{".zdebug_dynsym", ".dynstr"})
}

// zdebugBombELF names its dynamic string table ".zdebug" and makes it a
// zlib bomb of n zero bytes.
func zdebugBombELF(n int) []byte {
	dyn := make([]byte, 32) // DT_NEEDED 1, DT_NULL
	binary.LittleEndian.PutUint64(dyn, uint64(elf.DT_NEEDED))
	binary.LittleEndian.PutUint64(dyn[8:], 1)
	return namedELF([]elf.Section64{
		{Type: uint32(elf.SHT_DYNSYM), Link: 2, Entsize: 24},
		{Type: uint32(elf.SHT_STRTAB)},
		{Type: uint32(elf.SHT_DYNAMIC), Link: 2, Entsize: 16},
	}, [][]byte{make([]byte, 48), zdebug(make([]byte, n)), dyn}, []string{".dynsym", ".zdebug_dynstr", ".dynamic"})
}

// longNamesPE builds a PE32+ with n section headers all named "/4": the
// NUL-less strLen-byte run at the start of the COFF string table, which
// debug/pe copies once per section.
func longNamesPE(n, strLen int) []byte {
	var b bytes.Buffer
	dos := make([]byte, 0x40)
	copy(dos, "MZ")
	binary.LittleEndian.PutUint32(dos[0x3c:], 0x40)
	b.Write(dos)
	b.WriteString("PE\x00\x00")
	strOff := 0x40 + 4 + 20 + 240 + 40*n
	binary.Write(&b, binary.LittleEndian, pe.FileHeader{Machine: pe.IMAGE_FILE_MACHINE_AMD64, NumberOfSections: uint16(n),
		PointerToSymbolTable: uint32(strOff), SizeOfOptionalHeader: 240,
		Characteristics: pe.IMAGE_FILE_EXECUTABLE_IMAGE | pe.IMAGE_FILE_LARGE_ADDRESS_AWARE})
	binary.Write(&b, binary.LittleEndian, pe.OptionalHeader64{Magic: 0x20b, ImageBase: 0x140000000, SectionAlignment: 0x1000,
		FileAlignment: 0x200, SizeOfHeaders: uint32(strOff), NumberOfRvaAndSizes: 16})
	sh := pe.SectionHeader32{}
	copy(sh.Name[:], "/4")
	for range n {
		binary.Write(&b, binary.LittleEndian, sh)
	}
	binary.Write(&b, binary.LittleEndian, uint32(4+strLen))
	b.Write(bytes.Repeat([]byte("a"), strLen))
	return b.Bytes()
}

// heapSlack is the fixed allocation allowance on top of 16 bytes per file
// byte: the engine's own buffers, rule tables and report.
const heapSlack = 128 << 20

// TestFormatBudget: crafted header tables must not make the format task run
// (or keep the file mapped) far past the analysis budget.
func TestFormatBudget(t *testing.T) {
	cases := []struct {
		name, format, finding string
		data                  []byte
	}{
		{"overlapping ELF sections", "ELF", "overlapping-sections", overlapELF(20000, 2<<20)},
		{"many PE import descriptors", "PE", "pe-import-anomaly", manyDescriptorPE(100000, 4<<20)},
		{"Mach-O signature index", "Mach-O", "macho-sig-anomaly", sigBlobMachO(200000, 2<<20)},
		{"Mach-O fat arches", "Mach-O (universal)", "macho-many-arches", fatArchesMachO(31, 30000)},
		{"Mach-O load command flood", "Mach-O (universal)", "macho-table-anomaly", fatArchesMachO(31, 1_000_000)},
		{"PE COFF relocations", "PE", "pe-reloc-anomaly", relocPE(20000)},
		{"ELF PT_INTERP headers", "ELF", "elf-multiple-interp", interpELF(65535, 4<<20)},
		{"Mach-O overlapping symbol names", "Mach-O", "macho-table-anomaly", symtabMachO(1, 1<<15, 1<<20)},
		{"Mach-O repeated LC_SYMTAB", "Mach-O", "macho-table-anomaly", symtabMachO(20000, 1<<14, 1)},
		{"ELF overlapping section names", "ELF", "elf-table-anomaly", shnamesELF(30000, 2<<20)},
		{"ELF overlapping dynamic symbol names", "ELF", "elf-table-anomaly", dynELF(100000, 2<<20, 1)},
		{"ELF overlapping version records", "ELF", "elf-table-anomaly", dynELF(1, 1, 1<<16)},
		{"ELF .zdebug dynamic symbols", "ELF", "elf-table-anomaly", zdebugSymsELF(20000, 32<<10)},
		{"ELF .zdebug string table bomb", "ELF", "elf-table-anomaly", zdebugBombELF(64 << 20)},
		{"PE long section names", "PE", "pe-table-anomaly", longNamesPE(2000, 256<<10)},
	}
	// Generous for -race on a loaded machine; unbounded parsing takes far longer.
	budget := 2 * time.Second
	eng := newTestEngine(t, budget)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "crafted")
			if err := os.WriteFile(path, c.data, 0o600); err != nil {
				t.Fatal(err)
			}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			start := time.Now()
			r, released := eng.AnalyzeWait(context.Background(), path, Meta{})
			select {
			case <-released:
			case <-time.After(budget + 3*time.Second):
				t.Fatalf("analysis goroutines still running %v after start (budget %v)", time.Since(start), budget)
			}
			// Memory, like time, must stay linear in the file: allocation
			// amplification is the same attack as a stalled parser.
			runtime.ReadMemStats(&after)
			if alloc, limit := after.TotalAlloc-before.TotalAlloc, 16*uint64(len(c.data))+heapSlack; alloc > limit {
				t.Errorf("analysis allocated %d MiB for a %d KiB file (limit %d MiB)", alloc>>20, len(c.data)>>10, limit>>20)
			}
			if r.Format != c.format {
				t.Fatalf("format = %q, want %q", r.Format, c.format)
			}
			for _, tm := range r.Timings {
				if tm.Name == "format: "+c.format && tm.Status != "ok" {
					t.Errorf("format task status = %s (%s)", tm.Status, tm.Error)
				}
			}
			if _, ok := findingIDs(r)[c.finding]; !ok {
				t.Errorf("missing finding %s; got %v", c.finding, findingIDs(r))
			}
		})
	}
}

// TestFormatBudgetCancel: an expired context aborts format analysis with the
// context's error instead of finishing the work.
func TestFormatBudgetCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := analyzeELF(ctx, overlapELF(4, 1<<20)); err != context.Canceled {
		t.Errorf("analyzeELF err = %v, want context.Canceled", err)
	}
	if _, err := analyzePE(ctx, manyDescriptorPE(4, 1<<20)); err != context.Canceled {
		t.Errorf("analyzePE err = %v, want context.Canceled", err)
	}
}

// TestPEImportsMatchDebugPE: the bounded import walk must yield exactly what
// debug/pe does on a real binary, so imphashes do not change.
func TestPEImportsMatchDebugPE(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	for _, arch := range []string{"amd64", "386"} {
		data, err := os.ReadFile(goBuild(t, "benign", "windows", arch, "hello.exe"))
		if err != nil {
			t.Fatal(err)
		}
		f, err := pe.NewFile(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		want, _ := f.ImportedSymbols()
		got, anomaly, err := peImports(context.Background(), f, data)
		if err != nil || anomaly != "" || len(want) == 0 || !slices.Equal(got, want) {
			t.Errorf("%s: peImports = %v, %q, %v; debug/pe = %v", arch, got, anomaly, err, want)
		}
	}
}
