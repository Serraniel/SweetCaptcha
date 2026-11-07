//go:build !strictonly

// Package puzzle generates the interactive tasks shown only to questionable
// clients. Images are generated per challenge and answers stay on the server.
//
// Recognition grids are deliberately absent: the research in docs/research shows
// they are solved cheaply. These tasks are the less-broken interactive kinds,
// and they are an expiring margin rather than a security boundary, so a site can
// rotate or disable families. Each has a keyboard path. For anyone who cannot
// use them, the server also offers a slower compute path with no cognitive task.
package puzzle

import (
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"image/color"
	"math"
	"math/rand/v2"
	"slices"
)

// Family names.
const (
	LineTrace   = "line-trace"
	GapRings    = "gap-rings"
	RotateMatch = "rotate-match"
)

// Families lists every implemented family.
var Families = []string{LineTrace, GapRings, RotateMatch}

// Public is what the client sees. It never contains the answer.
type Public struct {
	Family string   `json:"family"`
	Images []string `json:"images"`
	// Options is the number of choices (line-trace), or columns*rows (gap-rings).
	Options int `json:"options,omitempty"`
	Columns int `json:"columns,omitempty"`
	Rows    int `json:"rows,omitempty"`
	// Markers is the number of questions to answer in a line-trace.
	Markers int `json:"markers,omitempty"`
}

// Answer is kept in the store and compared on submission.
type Answer struct {
	Family string `json:"family"`
	Values []int  `json:"values"`
}

// Generate creates a puzzle of the named family.
func Generate(family string) (Public, Answer, error) {
	var seed [32]byte
	if _, err := crand.Read(seed[:]); err != nil {
		return Public{}, Answer{}, err
	}
	r := rand.New(rand.NewChaCha8(seed))
	switch family {
	case LineTrace:
		return lineTrace(r)
	case GapRings:
		return gapRings(r)
	case RotateMatch:
		return rotateMatch(r)
	}
	return Public{}, Answer{}, fmt.Errorf("unknown puzzle family %q", family)
}

// Pick returns a random family from the allowed list.
func Pick(allowed []string) (string, error) {
	if len(allowed) == 0 {
		return "", errors.New("no puzzle families configured")
	}
	return allowed[rand.IntN(len(allowed))], nil
}

// Check compares a submission with the stored answer.
func Check(a Answer, submitted []int) bool {
	switch a.Family {
	case LineTrace:
		return slices.Equal(a.Values, submitted)
	case GapRings:
		got := slices.Clone(submitted)
		slices.Sort(got)
		return slices.Equal(a.Values, slices.Compact(got))
	case RotateMatch:
		if len(submitted) != len(a.Values) {
			return false
		}
		for i, want := range a.Values {
			if math.Abs(math.Remainder(float64(submitted[i]-want), 360)) > rotateTolerance {
				return false
			}
		}
		return true
	}
	return false
}

// EncodeAnswer serialises an answer for the store.
func EncodeAnswer(a Answer) (string, error) {
	b, err := json.Marshal(a)
	return string(b), err
}

// DecodeAnswer reverses EncodeAnswer.
func DecodeAnswer(s string) (Answer, error) {
	var a Answer
	return a, json.Unmarshal([]byte(s), &a)
}

var (
	paper = color.NRGBA{244, 245, 247, 255}
	ink   = color.NRGBA{58, 66, 82, 255}
)

const (
	lineCount       = 6
	rotateTolerance = 12.0
)

// lineTrace draws tangled curves. Two starts are marked (circle first, then
// square) and the answer is the number each line ends at. Vision models have
// been comparatively weak at following tangled lines, while people do it with no
// language or recognition skills.
func lineTrace(r *rand.Rand) (Public, Answer, error) {
	const w, h = 440, 300
	c := newCanvas(w, h, paper)
	palette := []color.NRGBA{{70, 96, 150, 255}, {126, 92, 150, 255}, {64, 130, 128, 255}}
	ends := r.Perm(lineCount)
	marked := r.Perm(lineCount)[:2]
	rowY := func(i int) float64 { return 34 + float64(i)*(h-68)/(lineCount-1) }
	for i := range lineCount {
		x0, y0 := 40.0, rowY(i)
		x3, y3 := float64(w-60), rowY(ends[i])
		x1, y1 := 120+r.Float64()*110, 10+r.Float64()*(h-20)
		x2, y2 := 200+r.Float64()*110, 10+r.Float64()*(h-20)
		col := palette[i%len(palette)]
		px, py := x0, y0
		const steps = 48
		for s := 1; s <= steps; s++ {
			t := float64(s) / steps
			u := 1 - t
			x := u*u*u*x0 + 3*u*u*t*x1 + 3*u*t*t*x2 + t*t*t*x3
			y := u*u*u*y0 + 3*u*u*t*y1 + 3*u*t*t*y2 + t*t*t*y3
			c.segment(px, py, x, y, 3, col)
			px, py = x, y
		}
		c.disc(x0, y0, 4, ink)
	}
	for i := range lineCount {
		c.digit(i+1, float64(w-44), rowY(i)-11, 11, 3, ink)
	}
	marker := color.NRGBA{200, 60, 50, 255}
	c.disc(40, rowY(marked[0]), 11, marker)
	y := rowY(marked[1])
	c.polygon([][2]float64{{29, y - 11}, {51, y - 11}, {51, y + 11}, {29, y + 11}}, marker)
	c.noise(r, 5)
	url, err := c.dataURL()
	if err != nil {
		return Public{}, Answer{}, err
	}
	return Public{Family: LineTrace, Images: []string{url}, Options: lineCount, Markers: 2},
		Answer{Family: LineTrace, Values: []int{ends[marked[0]], ends[marked[1]]}}, nil
}

// gapRings asks which cells hold a ring with a gap, in a Landolt C style. A
// distractor dot sits beside closed rings, so that "has an extra feature" fails.
func gapRings(r *rand.Rand) (Public, Answer, error) {
	const cols, rows, cell = 4, 3, 90
	c := newCanvas(cols*cell, rows*cell, paper)
	positives := 2 + r.IntN(3)
	order := r.Perm(cols * rows)
	isGap := map[int]bool{}
	for _, i := range order[:positives] {
		isGap[i] = true
	}
	values := []int{}
	for i := range cols * rows {
		cx := float64(i%cols)*cell + cell/2 + (r.Float64()-0.5)*14
		cy := float64(i/cols)*cell + cell/2 + (r.Float64()-0.5)*14
		radius := 22 + r.Float64()*10
		width := 4 + r.Float64()*3
		angle := r.Float64() * 2 * math.Pi
		if isGap[i] {
			values = append(values, i)
			c.ring(cx, cy, radius, width, angle, 0.45+r.Float64()*0.35, ink)
		} else {
			c.ring(cx, cy, radius, width, 0, 0, ink)
			if r.IntN(2) == 0 {
				c.disc(cx+math.Cos(angle)*(radius+8), cy+math.Sin(angle)*(radius+8), 2.5, ink)
			}
		}
	}
	c.noise(r, 6)
	url, err := c.dataURL()
	if err != nil {
		return Public{}, Answer{}, err
	}
	return Public{Family: GapRings, Images: []string{url}, Columns: cols, Rows: rows, Options: cols * rows},
		Answer{Family: GapRings, Values: values}, nil
}

// shape returns a random asymmetric polygon centred at the origin. A notch and
// an uneven outline make it unambiguous at any rotation.
func shape(r *rand.Rand) [][2]float64 {
	n := 9 + r.IntN(4)
	pts := make([][2]float64, n)
	notch := r.IntN(n)
	for i := range n {
		radius := 24 + r.Float64()*26
		if i == notch {
			radius = 12
		}
		a := 2 * math.Pi * float64(i) / float64(n)
		pts[i] = [2]float64{math.Cos(a) * radius, math.Sin(a) * radius}
	}
	return pts
}

func drawShape(pts [][2]float64, degrees float64, r *rand.Rand) (string, error) {
	const size = 120
	c := newCanvas(size, size, paper)
	sin, cos := math.Sincos(degrees * math.Pi / 180)
	out := make([][2]float64, len(pts))
	for i, p := range pts {
		out[i] = [2]float64{size/2 + p[0]*cos - p[1]*sin, size/2 + p[0]*sin + p[1]*cos}
	}
	c.polygon(out, ink)
	c.noise(r, 5)
	return c.dataURL()
}

// rotateMatch shows two pairs. Each pair is a reference and a rotated copy that
// the user turns with a slider or arrow keys. Two pairs reduce blind guessing to
// about 0.4% per attempt.
func rotateMatch(r *rand.Rand) (Public, Answer, error) {
	var images []string
	var values []int
	for range 2 {
		pts := shape(r)
		start := 40 + r.IntN(280)
		ref, err := drawShape(pts, 0, r)
		if err != nil {
			return Public{}, Answer{}, err
		}
		rot, err := drawShape(pts, float64(start), r)
		if err != nil {
			return Public{}, Answer{}, err
		}
		images = append(images, ref, rot)
		values = append(values, (360-start)%360)
	}
	return Public{Family: RotateMatch, Images: images, Options: len(values)}, Answer{Family: RotateMatch, Values: values}, nil
}
