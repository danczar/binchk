package analyze

import (
	"bytes"
	"context"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"os"
	"path/filepath"
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

// TestFormatBudget: crafted header tables must not make the format task run
// (or keep the file mapped) far past the analysis budget.
func TestFormatBudget(t *testing.T) {
	cases := []struct {
		name, format, finding string
		data                  []byte
	}{
		{"overlapping ELF sections", "ELF", "overlapping-sections", overlapELF(20000, 2<<20)},
		{"many PE import descriptors", "PE", "pe-import-anomaly", manyDescriptorPE(100000, 4<<20)},
	}
	budget := 500 * time.Millisecond
	eng := newTestEngine(t, budget)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "crafted")
			if err := os.WriteFile(path, c.data, 0o600); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			r, released := eng.AnalyzeWait(context.Background(), path, Meta{})
			select {
			case <-released:
			case <-time.After(budget + 3*time.Second):
				t.Fatalf("analysis goroutines still running %v after start (budget %v)", time.Since(start), budget)
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
