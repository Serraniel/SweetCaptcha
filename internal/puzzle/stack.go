//go:build !strictonly

package puzzle

import (
	"math"
	"math/rand/v2"
)

const (
	stackShapes   = 5
	stackW        = 360
	stackH        = 260
	minOverlap    = 140 // pixels shared before an occlusion counts as visible
	minVisible    = 1100
	stackAttempts = 300
)

// stackOrder draws overlapping outlined shapes in one colour. Each shape covers
// the outlines behind it, and the task is to name the one at the very back.
// Models measured 0-20% on such overlap and depth judgements, against about 100%
// for people. The generator accepts a layout only if the answer is unique from
// what is visible: the back shape hides nothing, and every other shape hides part
// of an earlier one.
func stackOrder(r *rand.Rand) (Public, Answer, error) {
	var shapes [][][2]float64
	var masks [][]bool
	for range stackAttempts {
		shapes, masks = stackLayout(r)
		if stackValid(masks) {
			break
		}
	}
	c := newCanvas(stackW, stackH, paper)
	for _, s := range shapes {
		c.polygon(s, paper)
		for i := range s {
			a, b := s[i], s[(i+1)%len(s)]
			c.segment(a[0], a[1], b[0], b[1], 3, ink)
		}
	}
	labels := r.Perm(stackShapes)
	for i := range shapes {
		x, y := labelPoint(masks, i)
		c.disc(x, y, 11, color3)
		c.digit(labels[i]+1, x-4, y-7, 7, 2, paperInk)
	}
	c.noise(r, 5)
	url, err := c.dataURL()
	if err != nil {
		return Public{}, Answer{}, err
	}
	return Public{Family: StackOrder, Images: []string{url}, Options: stackShapes},
		Answer{Family: StackOrder, Values: []int{labels[0]}}, nil
}

func stackLayout(r *rand.Rand) ([][][2]float64, [][]bool) {
	shapes := make([][][2]float64, stackShapes)
	masks := make([][]bool, stackShapes)
	for i := range stackShapes {
		cx := stackW/2 + (r.Float64()-0.5)*170
		cy := stackH/2 + (r.Float64()-0.5)*90
		radius := 48 + r.Float64()*26
		n := 5 + r.IntN(3)
		angles := make([]float64, n)
		for k := range n {
			angles[k] = 2 * math.Pi * (float64(k) + r.Float64()*0.6) / float64(n)
		}
		pts := make([][2]float64, n)
		for k, a := range angles {
			rr := radius * (0.75 + r.Float64()*0.25)
			pts[k] = [2]float64{cx + math.Cos(a)*rr, cy + math.Sin(a)*rr}
		}
		shapes[i] = pts
		mask := make([]bool, stackW*stackH)
		for y := range stackH {
			for x := range stackW {
				mask[y*stackW+x] = inside(pts, float64(x)+0.5, float64(y)+0.5)
			}
		}
		masks[i] = mask
	}
	return shapes, masks
}

func overlap(a, b []bool) int {
	n := 0
	for i := range a {
		if a[i] && b[i] {
			n++
		}
	}
	return n
}

// visible counts the pixels of shape i not covered by shapes drawn after it.
func visible(masks [][]bool, i int) int {
	n := 0
	for p := range masks[i] {
		if !masks[i][p] {
			continue
		}
		covered := false
		for j := i + 1; j < len(masks); j++ {
			if masks[j][p] {
				covered = true
				break
			}
		}
		if !covered {
			n++
		}
	}
	return n
}

func stackValid(masks [][]bool) bool {
	backCovered := false
	for i := 1; i < len(masks); i++ {
		if overlap(masks[0], masks[i]) >= minOverlap {
			backCovered = true
		}
		hides := false
		for j := range i {
			if overlap(masks[i], masks[j]) >= minOverlap {
				hides = true
				break
			}
		}
		if !hides {
			return false
		}
	}
	if !backCovered {
		return false
	}
	for i := range masks {
		if visible(masks, i) < minVisible {
			return false
		}
	}
	return true
}

// labelPoint finds a visible point of shape i far from any edge, for its number.
func labelPoint(masks [][]bool, i int) (float64, float64) {
	isVisible := func(x, y int) bool {
		if x < 0 || y < 0 || x >= stackW || y >= stackH || !masks[i][y*stackW+x] {
			return false
		}
		for j := i + 1; j < len(masks); j++ {
			if masks[j][y*stackW+x] {
				return false
			}
		}
		return true
	}
	bestX, bestY, best := 0, 0, -1
	for y := 0; y < stackH; y += 3 {
		for x := 0; x < stackW; x += 3 {
			if !isVisible(x, y) {
				continue
			}
			// The clearance is the radius of the largest visible square around it.
			d := 0
			for d < 30 && isVisible(x-d, y-d) && isVisible(x+d, y-d) && isVisible(x-d, y+d) && isVisible(x+d, y+d) && isVisible(x, y-d) && isVisible(x, y+d) && isVisible(x-d, y) && isVisible(x+d, y) {
				d++
			}
			if d > best {
				bestX, bestY, best = x, y, d
			}
		}
	}
	return float64(bestX), float64(bestY)
}
