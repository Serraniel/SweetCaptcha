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

// Kinetic task geometry. Frames are rendered at this logical size and shown at
// twice the size with pixelated scaling.
const (
	kineticCell   = 40
	kineticGrid   = 3
	kineticFrames = 40
	kineticFPS    = 25
	kineticTile   = 64
)

// kinetic hides shapes in moving noise. Inside a shape the dots drift one way and
// outside they drift the other way, so the shape exists only in motion: every
// single frame is uniform noise. People see it at once when the animation plays.
// Vision models and screenshot-driven agents measured near 0% on such stimuli.
//
// The frames are rendered here, because a client renderer would need the shape
// masks, which are the answer. They are sent as a PNG sprite sheet of full
// frames, which carries no motion vectors. A dedicated solver can still recover
// the shapes by comparing frames, so this resists general AI, not purpose-built
// tools.
func kinetic(r *rand.Rand) (Public, Answer, error) {
	const size = kineticCell * kineticGrid
	cells := kineticGrid * kineticGrid
	order := r.Perm(cells)
	targets := 2 + r.IntN(3)
	isTarget := map[int]bool{}
	var values []int
	for _, i := range order[:targets] {
		isTarget[i] = true
	}
	type cell struct {
		inside func(x, y float64) bool
		dx, dy int
		bg, fg []bool
	}
	cs := make([]cell, cells)
	dirs := [][2]int{{1, 0}, {-1, 0}, {0, 1}, {0, -1}, {1, 1}, {-1, -1}, {1, -1}, {-1, 1}}
	for i := range cells {
		if isTarget[i] {
			values = append(values, i)
		}
		cx := kineticCell/2 + (r.Float64()-0.5)*6
		cy := kineticCell/2 + (r.Float64()-0.5)*6
		var inside func(x, y float64) bool
		switch {
		case isTarget[i]:
			outer := 12.5 + r.Float64()*2
			inner := outer - 5
			inside = func(x, y float64) bool {
				d := math.Hypot(x-cx, y-cy)
				return d <= outer && d >= inner
			}
		case r.IntN(10) < 7:
			inside = decoyShape(r, cx, cy)
		default:
			inside = func(float64, float64) bool { return false }
		}
		d := dirs[r.IntN(len(dirs))]
		cs[i] = cell{inside, d[0], d[1], noiseTile(r), noiseTile(r)}
	}
	// One frame per row of the sprite sheet: black and a mid grey keep the average
	// brightness of every area constant, which stays clear of flash thresholds.
	pal := color.Palette{color.Gray{Y: 92}, color.Gray{Y: 168}}
	sheet := image.NewPaletted(image.Rect(0, 0, size, size*kineticFrames), pal)
	for t := range kineticFrames {
		for y := range size {
			for x := range size {
				c := cs[(y/kineticCell)*kineticGrid+x/kineticCell]
				lx, ly := x%kineticCell, y%kineticCell
				var on bool
				if c.inside(float64(lx)+0.5, float64(ly)+0.5) {
					on = c.fg[wrap(lx+c.dx*t)*kineticTile+wrap(ly+c.dy*t)]
				} else {
					on = c.bg[wrap(lx-c.dx*t)*kineticTile+wrap(ly-c.dy*t)]
				}
				// A few dots flicker each frame, so that dots have a limited life.
				if r.IntN(100) < 3 {
					on = !on
				}
				if on {
					sheet.SetColorIndex(x, t*size+y, 0)
				} else {
					sheet.SetColorIndex(x, t*size+y, 1)
				}
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, sheet); err != nil {
		return Public{}, Answer{}, err
	}
	return Public{
			Family: Kinetic, Columns: kineticGrid, Rows: kineticGrid, Options: cells,
			Images: []string{"data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())},
			Frames: kineticFrames, FPS: kineticFPS, FrameSize: size,
		},
		Answer{Family: Kinetic, Values: values}, nil
}

func wrap(v int) int { return ((v % kineticTile) + kineticTile) % kineticTile }

func noiseTile(r *rand.Rand) []bool {
	t := make([]bool, kineticTile*kineticTile)
	for i := range t {
		t[i] = r.IntN(100) < 42
	}
	return t
}

// decoyShape returns a filled shape of similar size to the ring, so that only its
// form tells it apart, not its presence or motion.
func decoyShape(r *rand.Rand, cx, cy float64) func(x, y float64) bool {
	switch r.IntN(3) {
	case 0:
		radius := 10 + r.Float64()*3
		return func(x, y float64) bool { return math.Hypot(x-cx, y-cy) <= radius }
	case 1:
		half := 9 + r.Float64()*3
		return func(x, y float64) bool { return math.Abs(x-cx) <= half && math.Abs(y-cy) <= half }
	default:
		h := 12 + r.Float64()*3
		return func(x, y float64) bool {
			dy := y - (cy - h)
			return dy >= 0 && dy <= 2*h && math.Abs(x-cx) <= dy*0.6
		}
	}
}
