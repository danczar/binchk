// Command mkicon renders binchk's application icon and writes every format
// the release builds need:
//
//	assets/icon/binchk-<size>.png   (16..1024)
//	assets/icon/binchk.icns         (macOS .app, via iconutil when available)
//	assets/icon/binchk.ico          (Windows, PNG-compressed entries)
//
// Run from the repository root: go run ./tools/mkicon
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
)

const outDir = "assets/icon"

type rgba struct{ r, g, b, a float64 } // premultiplied, 0..1

func hex(c uint32, a float64) rgba {
	return rgba{float64(c>>16&0xff) / 255 * a, float64(c>>8&0xff) / 255 * a, float64(c&0xff) / 255 * a, a}
}

// over composites src over dst (both premultiplied).
func over(dst, src rgba) rgba {
	k := 1 - src.a
	return rgba{src.r + dst.r*k, src.g + dst.g*k, src.b + dst.b*k, src.a + dst.a*k}
}

func lerp(a, b rgba, t float64) rgba {
	t = math.Max(0, math.Min(1, t))
	return rgba{a.r + (b.r-a.r)*t, a.g + (b.g-a.g)*t, a.b + (b.b-a.b)*t, a.a + (b.a-a.a)*t}
}

// ---- geometry, in unit coordinates (0..1, y down) ----

// body returns the superellipse "squircle" test, Apple's icon shape.
func inBody(x, y, margin float64) bool {
	half := 0.5 - margin
	if half <= 0 {
		return false
	}
	u, v := math.Abs(x-0.5)/half, math.Abs(y-0.5)/half
	return math.Pow(u, 5)+math.Pow(v, 5) <= 1
}

// shield: flat top with rounded shoulders, straight sides, curved point.
func inShield(x, y, cx, top, w, h float64) bool {
	mid := top + h*0.47
	bottom := top + h
	if y < top || y > bottom {
		return false
	}
	half := w / 2
	// soften the top corners
	if y < top+h*0.08 {
		t := (top + h*0.08 - y) / (h * 0.08)
		half -= w * 0.06 * (1 - math.Sqrt(1-t*t))
	}
	if y > mid {
		t := (y - mid) / (bottom - mid)
		half *= math.Sqrt(math.Max(0, 1-math.Pow(t, 2.4)))
	}
	return math.Abs(x-cx) <= half
}

func segDist(x, y, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	t := math.Max(0, math.Min(1, ((x-ax)*dx+(y-ay)*dy)/(dx*dx+dy*dy)))
	return math.Hypot(x-(ax+t*dx), y-(ay+t*dy))
}

// ---- the icon ----

type style struct {
	margin float64 // transparent border around the body (macOS grid ≈ 0.1)
	detail bool    // binary-dot texture (dropped at tiny sizes)
}

var (
	bgTop    = hex(0x26325c, 1)
	bgBottom = hex(0x0b1022, 1)
	shTop    = hex(0x4ade9a, 1)
	shBottom = hex(0x0e8f5d, 1)
	shEdge   = hex(0x065f46, 1)
	white    = hex(0xffffff, 1)
)

// bits is a fixed pseudo-random binary pattern for the background texture.
var bits = func() [16][16]bool {
	var b [16][16]bool
	s := uint32(0x9e3779b9)
	for i := range b {
		for j := range b[i] {
			s ^= s << 13
			s ^= s >> 17
			s ^= s << 5
			b[i][j] = s&1 == 1
		}
	}
	return b
}()

// sample returns the colour at one sub-pixel position.
func sample(x, y float64, st style) rgba {
	var c rgba
	if !inBody(x, y, st.margin) {
		return c
	}
	m := st.margin
	ny := (y - m) / (1 - 2*m) // 0..1 within the body
	c = lerp(bgTop, bgBottom, ny)
	// soft top glow
	c = over(c, hex(0x6d83d9, 0.18*math.Max(0, 1-math.Hypot(x-0.5, y-m)*2.2)))

	// binary texture: rings (0) and dots (1) on a grid, fading downward
	if st.detail {
		n := 12.0
		gx, gy := (x-m)/(1-2*m)*n, ny*n
		cx, cy := math.Floor(gx)+0.5, math.Floor(gy)+0.5
		d := math.Hypot(gx-cx, gy-cy)
		on := bits[int(cy)%16][int(cx)%16]
		fade := 0.13 * (1 - ny*0.85)
		if (on && d < 0.16) || (!on && d > 0.13 && d < 0.22) {
			c = over(c, hex(0x9fb4ff, fade))
		}
	}

	// shield drop shadow
	const cx, top, w, h = 0.5, 0.2, 0.52, 0.62
	if inShield(x, y-0.025, cx, top, w*1.02, h) {
		c = over(c, hex(0x000000, 0.35))
	}
	if inShield(x, y, cx, top, w, h) {
		t := (y - top) / h
		sc := lerp(shTop, shBottom, t)
		// edge band
		inner := inShield(x, y, cx, top+h*0.035, w*0.9, h*0.93)
		if !inner {
			sc = shEdge
		} else {
			// left-hand sheen: brighter left half, like light from above-left
			if x < cx {
				sc = over(sc, hex(0xffffff, 0.10))
			}
		}
		c = over(c, sc)
		// check mark
		lw := 0.055
		p1x, p1y := 0.355, 0.49
		p2x, p2y := 0.465, 0.60
		p3x, p3y := 0.655, 0.375
		d := math.Min(segDist(x, y, p1x, p1y, p2x, p2y), segDist(x, y, p2x, p2y, p3x, p3y))
		if d < lw {
			c = over(c, white)
		}
	}
	return c
}

func render(size int, st style) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	ss := 4
	if size <= 64 {
		ss = 8
	}
	var wg sync.WaitGroup
	rows := make(chan int, size)
	for y := 0; y < size; y++ {
		rows <- y
	}
	close(rows)
	for w := 0; w < runtime.NumCPU(); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for py := range rows {
				for px := 0; px < size; px++ {
					var acc rgba
					for sy := 0; sy < ss; sy++ {
						for sx := 0; sx < ss; sx++ {
							x := (float64(px) + (float64(sx)+0.5)/float64(ss)) / float64(size)
							y := (float64(py) + (float64(sy)+0.5)/float64(ss)) / float64(size)
							s := sample(x, y, st)
							acc.r, acc.g, acc.b, acc.a = acc.r+s.r, acc.g+s.g, acc.b+s.b, acc.a+s.a
						}
					}
					n := float64(ss * ss)
					a := acc.a / n
					if a == 0 {
						continue
					}
					img.SetNRGBA(px, py, color.NRGBA{
						uint8(math.Round(acc.r / n / a * 255)), uint8(math.Round(acc.g / n / a * 255)),
						uint8(math.Round(acc.b / n / a * 255)), uint8(math.Round(a * 255)),
					})
				}
			}
		}()
	}
	wg.Wait()
	return img
}

func encodePNG(img image.Image) []byte {
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		log.Fatal(err)
	}
	return b.Bytes()
}

// styleFor: macOS icons keep Apple's ~10% grid margin; small Windows/Linux
// sizes fill the square and drop the texture so the shield stays legible.
func styleFor(size int, mac bool) style {
	if mac {
		return style{margin: 0.098, detail: size >= 64}
	}
	return style{margin: 0.02, detail: size >= 48}
}

func writeICO(path string, sizes []int) {
	var imgs [][]byte
	for _, s := range sizes {
		imgs = append(imgs, encodePNG(render(s, styleFor(s, false))))
	}
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, [3]uint16{0, 1, uint16(len(sizes))})
	off := 6 + 16*len(sizes)
	for i, s := range sizes {
		dim := byte(s)
		if s >= 256 {
			dim = 0
		}
		b.Write([]byte{dim, dim, 0, 0})
		binary.Write(&b, binary.LittleEndian, [2]uint16{1, 32})
		binary.Write(&b, binary.LittleEndian, [2]uint32{uint32(len(imgs[i])), uint32(off)})
		off += len(imgs[i])
	}
	for _, p := range imgs {
		b.Write(p)
	}
	must(os.WriteFile(path, b.Bytes(), 0o644))
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	must(os.MkdirAll(outDir, 0o755))

	// PNGs for Linux (.desktop) and documentation.
	for _, s := range []int{16, 32, 48, 64, 128, 256, 512, 1024} {
		must(os.WriteFile(filepath.Join(outDir, fmt.Sprintf("binchk-%d.png", s)), encodePNG(render(s, styleFor(s, false))), 0o644))
	}

	// Windows .ico
	writeICO(filepath.Join(outDir, "binchk.ico"), []int{16, 20, 24, 32, 40, 48, 64, 256})

	// macOS .icns via an .iconset
	set := filepath.Join(os.TempDir(), "binchk.iconset")
	os.RemoveAll(set)
	must(os.MkdirAll(set, 0o755))
	for _, s := range []int{16, 32, 128, 256, 512} {
		must(os.WriteFile(filepath.Join(set, fmt.Sprintf("icon_%dx%d.png", s, s)), encodePNG(render(s, styleFor(s, true))), 0o644))
		must(os.WriteFile(filepath.Join(set, fmt.Sprintf("icon_%dx%d@2x.png", s, s)), encodePNG(render(2*s, styleFor(2*s, true))), 0o644))
	}
	if _, err := exec.LookPath("iconutil"); err == nil {
		out, err := exec.Command("iconutil", "-c", "icns", "-o", filepath.Join(outDir, "binchk.icns"), set).CombinedOutput()
		if err != nil {
			log.Fatalf("iconutil: %v\n%s", err, out)
		}
	} else {
		log.Print("iconutil not found (not on macOS): skipping binchk.icns")
	}
	os.RemoveAll(set)
	log.Printf("wrote icons to %s", outDir)
}
