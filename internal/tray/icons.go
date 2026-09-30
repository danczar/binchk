package tray

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
	"runtime"
)

// Icons are drawn at startup instead of shipping image files: a shield with
// a check mark, anti-aliased by 4x4 supersampling.
type iconSet struct {
	idle, template, scanning, clean, suspicious, malicious []byte
}

var icons = func() iconSet {
	const size = 64
	return iconSet{
		idle:       encode(drawShield(size, color.NRGBA{0x5f, 0x66, 0x73, 0xff}, true)),
		template:   encode(drawShield(size, color.NRGBA{0, 0, 0, 0xff}, true)),
		scanning:   encode(drawShield(size, color.NRGBA{0x2f, 0x6f, 0xd3, 0xff}, false)),
		clean:      encode(drawShield(size, color.NRGBA{0x1f, 0x8a, 0x4c, 0xff}, true)),
		suspicious: encode(drawShield(size, color.NRGBA{0xe0, 0x8a, 0x00, 0xff}, false)),
		malicious:  encode(drawShield(size, color.NRGBA{0xd3, 0x2f, 0x2f, 0xff}, false)),
	}
}()

// inShield reports whether (x,y) in unit coordinates lies inside the shield.
func inShield(x, y float64) bool {
	const top, mid, bottom, half = 0.06, 0.52, 0.96, 0.40
	if y < top || y > bottom {
		return false
	}
	w := half
	if y > mid {
		t := (y - mid) / (bottom - mid)
		w = half * math.Sqrt(math.Max(0, 1-t*t*t))
	}
	return math.Abs(x-0.5) <= w
}

// inCheck is a check mark; inBang an exclamation mark.
func inCheck(x, y float64) bool {
	d := func(ax, ay, bx, by float64) float64 {
		dx, dy := bx-ax, by-ay
		t := math.Max(0, math.Min(1, ((x-ax)*dx+(y-ay)*dy)/(dx*dx+dy*dy)))
		px, py := ax+t*dx, ay+t*dy
		return math.Hypot(x-px, y-py)
	}
	return d(0.30, 0.47, 0.45, 0.62) < 0.065 || d(0.45, 0.62, 0.72, 0.32) < 0.065
}

func inBang(x, y float64) bool {
	if math.Abs(x-0.5) < 0.065 && y > 0.22 && y < 0.55 {
		return true
	}
	return math.Hypot(x-0.5, y-0.68) < 0.075
}

func drawShield(size int, c color.NRGBA, check bool) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	const ss = 4
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var fill, glyph int
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/ss) / float64(size)
					y := (float64(py) + (float64(sy)+0.5)/ss) / float64(size)
					if inShield(x, y) {
						fill++
						if (check && inCheck(x, y)) || (!check && inBang(x, y)) {
							glyph++
						}
					}
				}
			}
			if fill == 0 {
				continue
			}
			// Glyph is punched out (transparent) so template icons work in
			// both light and dark menu bars.
			a := float64(fill-glyph) / (ss * ss)
			img.SetNRGBA(px, py, color.NRGBA{c.R, c.G, c.B, uint8(a * float64(c.A))})
		}
	}
	return img
}

func encode(img image.Image) []byte {
	var b bytes.Buffer
	_ = png.Encode(&b, img)
	if runtime.GOOS == "windows" {
		return pngToICO(b.Bytes(), img.Bounds().Dx())
	}
	return b.Bytes()
}

// pngToICO wraps a PNG in a single-image ICO container (Vista+).
func pngToICO(p []byte, size int) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, [3]uint16{0, 1, 1})
	dim := byte(size)
	if size >= 256 {
		dim = 0
	}
	b.Write([]byte{dim, dim, 0, 0})
	binary.Write(&b, binary.LittleEndian, [2]uint16{1, 32})
	binary.Write(&b, binary.LittleEndian, [2]uint32{uint32(len(p)), 22})
	b.Write(p)
	return b.Bytes()
}
