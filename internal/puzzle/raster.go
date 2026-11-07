//go:build !strictonly

package puzzle

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"math"
	"math/rand/v2"
)

// canvas is a small anti-aliased rasteriser. It uses the standard library only,
// so puzzle generation adds no dependency and needs no external assets.
type canvas struct{ img *image.NRGBA }

func newCanvas(w, h int, bg color.NRGBA) *canvas {
	c := &canvas{img: image.NewNRGBA(image.Rect(0, 0, w, h))}
	for i := 0; i < len(c.img.Pix); i += 4 {
		c.img.Pix[i], c.img.Pix[i+1], c.img.Pix[i+2], c.img.Pix[i+3] = bg.R, bg.G, bg.B, 255
	}
	return c
}

func (c *canvas) blend(x, y int, col color.NRGBA, cover float64) {
	if cover <= 0 || !(image.Pt(x, y).In(c.img.Rect)) {
		return
	}
	if cover > 1 {
		cover = 1
	}
	i := c.img.PixOffset(x, y)
	for k, v := range [3]uint8{col.R, col.G, col.B} {
		c.img.Pix[i+k] = uint8(float64(c.img.Pix[i+k])*(1-cover) + float64(v)*cover)
	}
}

// segment draws a round-capped line.
func (c *canvas) segment(x0, y0, x1, y1, width float64, col color.NRGBA) {
	r := width / 2
	minX, maxX := int(math.Min(x0, x1)-r-1), int(math.Max(x0, x1)+r+2)
	minY, maxY := int(math.Min(y0, y1)-r-1), int(math.Max(y0, y1)+r+2)
	dx, dy := x1-x0, y1-y0
	l2 := dx*dx + dy*dy
	for y := minY; y < maxY; y++ {
		for x := minX; x < maxX; x++ {
			px, py := float64(x)+0.5, float64(y)+0.5
			t := 0.0
			if l2 > 0 {
				t = math.Max(0, math.Min(1, ((px-x0)*dx+(py-y0)*dy)/l2))
			}
			d := math.Hypot(px-x0-t*dx, py-y0-t*dy)
			c.blend(x, y, col, r-d+0.5)
		}
	}
}

func (c *canvas) disc(x, y, r float64, col color.NRGBA) { c.segment(x, y, x, y, 2*r, col) }

// ring draws an annulus with an optional gap centred on gapAt, both in radians.
func (c *canvas) ring(cx, cy, r, width, gapAt, gapWidth float64, col color.NRGBA) {
	bound := int(r + width + 2)
	for y := int(cy) - bound; y <= int(cy)+bound; y++ {
		for x := int(cx) - bound; x <= int(cx)+bound; x++ {
			px, py := float64(x)+0.5-cx, float64(y)+0.5-cy
			d := math.Hypot(px, py)
			cover := width/2 - math.Abs(d-r) + 0.5
			if gapWidth > 0 {
				diff := math.Abs(math.Remainder(math.Atan2(py, px)-gapAt, 2*math.Pi))
				edge := (diff - gapWidth/2) * r
				cover = math.Min(cover, edge+0.5)
			}
			c.blend(x, y, col, cover)
		}
	}
}

// polygon fills a polygon with 3x3 supersampling.
func (c *canvas) polygon(pts [][2]float64, col color.NRGBA) {
	minX, minY, maxX, maxY := math.Inf(1), math.Inf(1), math.Inf(-1), math.Inf(-1)
	for _, p := range pts {
		minX, maxX = math.Min(minX, p[0]), math.Max(maxX, p[0])
		minY, maxY = math.Min(minY, p[1]), math.Max(maxY, p[1])
	}
	for y := int(minY) - 1; y <= int(maxY)+1; y++ {
		for x := int(minX) - 1; x <= int(maxX)+1; x++ {
			hits := 0
			for sy := range 3 {
				for sx := range 3 {
					if inside(pts, float64(x)+(float64(sx)+0.5)/3, float64(y)+(float64(sy)+0.5)/3) {
						hits++
					}
				}
			}
			c.blend(x, y, col, float64(hits)/9)
		}
	}
}

func inside(pts [][2]float64, x, y float64) bool {
	in := false
	for i, j := 0, len(pts)-1; i < len(pts); j, i = i, i+1 {
		a, b := pts[i], pts[j]
		if (a[1] > y) != (b[1] > y) && x < (b[0]-a[0])*(y-a[1])/(b[1]-a[1])+a[0] {
			in = !in
		}
	}
	return in
}

// digit draws 0-9 with seven strokes, so no font has to be bundled.
func (c *canvas) digit(n int, x, y, size, width float64, col color.NRGBA) {
	seg := [7][4]float64{
		{0, 0, 1, 0}, {1, 0, 1, 1}, {1, 1, 1, 2}, {0, 2, 1, 2}, {0, 1, 0, 2}, {0, 0, 0, 1}, {0, 1, 1, 1},
	}
	on := [10]string{"abcdef", "bc", "abged", "abgcd", "fgbc", "afgcd", "afgedc", "abc", "abcdefg", "abcfgd"}[n]
	for _, s := range on {
		g := seg[s-'a']
		c.segment(x+g[0]*size, y+g[1]*size, x+g[2]*size, y+g[3]*size, width, col)
	}
}

// noise adds speckle, which makes the image less trivially segmentable.
func (c *canvas) noise(r *rand.Rand, amount int) {
	for i := 0; i < len(c.img.Pix); i += 4 {
		d := r.IntN(2*amount+1) - amount
		for k := range 3 {
			c.img.Pix[i+k] = uint8(max(0, min(255, int(c.img.Pix[i+k])+d)))
		}
	}
}

func (c *canvas) dataURL() (string, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, c.img); err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
