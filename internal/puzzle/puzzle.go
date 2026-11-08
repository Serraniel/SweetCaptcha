//go:build !strictonly

// Package puzzle generates the interactive tasks shown only to questionable
// clients. Images are generated per challenge and answers stay on the server.
//
// Recognition grids are deliberately absent: the research in docs/research shows
// they are solved cheaply. These tasks are the less-broken interactive kinds,
// and they are an expiring margin rather than a security boundary, so a site can
// rotate or disable families. Each has a keyboard path. internal/server decides
// when a slower compute path may be offered instead.
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
			if math.Abs(math.Remainder(float64(submitted[i]-want), 360)) > rotateTolerance { //nolint:gosec // The lengths were compared above.
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
	// lineInk is one colour for every line. See lineTrace.
	lineInk = color.NRGBA{70, 96, 150, 255}
)

const (
	lineCount       = 6
	layoutAttempts  = 200
	closeDistance   = 10.0
	maxCloseRun     = 6
	minCrossings    = 2
	rotateTolerance = 20.0
)

// lineTrace draws crossing curves in one colour. Two starts are marked (circle
// first, then square) and the answer is the number each line ends at.
//
// All lines share a colour on purpose. Colour would let a script separate them
// with a simple filter, and it does not help people who can't tell the hues apart.
// In exchange, the layout must be readable by shape alone: lines may cross but may
// not run alongside each other, which layoutLines enforces.
func lineTrace(r *rand.Rand) (Public, Answer, error) {
	const w, h = 440, 300
	c := newCanvas(w, h, paper)
	rowY := func(i int) float64 { return 34 + float64(i)*(h-68)/(lineCount-1) }
	ends, marked, curves := layoutLines(r, w, h, rowY)
	for _, curve := range curves {
		for s := 1; s < len(curve); s++ {
			c.segment(curve[s-1][0], curve[s-1][1], curve[s][0], curve[s][1], 3, lineInk)
		}
		c.disc(curve[0][0], curve[0][1], 4, ink)
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

// layoutLines samples layouts until one is readable. It returns the best layout
// found if none qualifies, which the tests show does not happen in practice.
func layoutLines(r *rand.Rand, w, h int, rowY func(int) float64) (ends, marked []int, curves [][][2]float64) {
	best := -1
	for range layoutAttempts {
		e := r.Perm(lineCount)
		m := r.Perm(lineCount)[:2]
		cs := make([][][2]float64, lineCount)
		for i := range lineCount {
			cs[i] = bezier(r, 40, rowY(i), float64(w-60), rowY(e[i]), h)
		}
		run := longestCloseRun(cs)
		crossed := min(crossings(cs, m[0]), crossings(cs, m[1]))
		if best < 0 || (crossed >= minCrossings && run < best) {
			best, ends, marked, curves = run, e, m, cs
		}
		if crossed >= minCrossings && run <= maxCloseRun {
			return e, m, cs
		}
	}
	return ends, marked, curves
}

// bezier draws an S-curve that leaves and arrives near horizontal. Lines therefore
// meet in the middle at a clear angle, instead of sharing a long stretch.
func bezier(r *rand.Rand, x0, y0, x3, y3 float64, h int) [][2]float64 {
	jitter := func() float64 { return (r.Float64() - 0.5) * 50 }
	limit := func(y float64) float64 { return max(10, min(float64(h-10), y)) }
	x1, y1 := 130+r.Float64()*60, limit(y0+jitter())
	x2, y2 := 240+r.Float64()*60, limit(y3+jitter())
	const steps = 48
	out := make([][2]float64, steps+1)
	for s := range steps + 1 {
		t := float64(s) / steps
		u := 1 - t
		out[s] = [2]float64{
			u*u*u*x0 + 3*u*u*t*x1 + 3*u*t*t*x2 + t*t*t*x3,
			u*u*u*y0 + 3*u*u*t*y1 + 3*u*t*t*y2 + t*t*t*y3,
		}
	}
	return out
}

// longestCloseRun returns the most consecutive points on any curve that lie within
// closeDistance of another single curve. A clean crossing gives a short run, and
// two lines travelling together give a long one.
func longestCloseRun(curves [][][2]float64) int {
	longest := 0
	for i, a := range curves {
		for j, b := range curves {
			if i == j {
				continue
			}
			run := 0
			for _, p := range a {
				near := false
				for _, q := range b {
					if math.Hypot(p[0]-q[0], p[1]-q[1]) < closeDistance {
						near = true
						break
					}
				}
				if near {
					run++
					longest = max(longest, run)
					if longest > maxCloseRun {
						return longest // Already rejected, so stop early.
					}
				} else {
					run = 0
				}
			}
		}
	}
	return longest
}

// crossings counts how many other lines the given line crosses.
func crossings(curves [][][2]float64, line int) int {
	count := 0
	for j, other := range curves {
		if j != line && intersects(curves[line], other) {
			count++
		}
	}
	return count
}

func intersects(a, b [][2]float64) bool {
	side := func(p, q, x [2]float64) float64 { return (q[0]-p[0])*(x[1]-p[1]) - (q[1]-p[1])*(x[0]-p[0]) }
	for i := 1; i < len(a); i++ {
		for j := 1; j < len(b); j++ {
			if side(a[i-1], a[i], b[j-1])*side(a[i-1], a[i], b[j]) < 0 && side(b[j-1], b[j], a[i-1])*side(b[j-1], b[j], a[i]) < 0 {
				return true
			}
		}
	}
	return false
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

// shape returns a smooth, random, asymmetric outline centred at the origin. It
// stays inside the circle the widget clips it to at every rotation. A deep notch
// makes the orientation easy to judge.
func shape(r *rand.Rand) [][2]float64 {
	n := 7 + r.IntN(3)
	ctrl := make([][2]float64, n)
	notch := r.IntN(n)
	for i := range n {
		radius := 26 + r.Float64()*22
		if i == notch {
			radius = 10
		}
		a := 2 * math.Pi * float64(i) / float64(n)
		ctrl[i] = [2]float64{math.Cos(a) * radius, math.Sin(a) * radius}
	}
	// A closed Catmull-Rom spline through the control points rounds the outline.
	const perSegment = 8
	out := make([][2]float64, 0, n*perSegment)
	for i := range n {
		p0, p1, p2, p3 := ctrl[(i+n-1)%n], ctrl[i], ctrl[(i+1)%n], ctrl[(i+2)%n]
		for s := range perSegment {
			t := float64(s) / perSegment
			var q [2]float64
			for k := range 2 {
				q[k] = 0.5 * (2*p1[k] + (p2[k]-p0[k])*t + (2*p0[k]-5*p1[k]+4*p2[k]-p3[k])*t*t + (3*p1[k]-p0[k]-3*p2[k]+p3[k])*t*t*t)
			}
			out = append(out, q)
		}
	}
	return out
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
// about 1.2% per attempt.
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
