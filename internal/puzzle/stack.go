//go:build !strictonly

package puzzle

import (
	"math"
	"math/rand/v2"
)

const (
	stackShapes   = 6
	stackW        = 360
	stackH        = 260
	minOverlap    = 140 // pixels shared before an occlusion counts as visible
	minVisible    = 1300
	minClearance  = 13 // room for the number tag inside the visible part
	stackAttempts = 100
)

// stackOrder draws overlapping outlined shapes in one colour. Each shape covers
// the outlines behind it, and the task is to name the one at the very back.
// Models measured 0-20% on such overlap and depth judgements, against about 100%
// for people. Two questions, the back and the front shape, make a blind guess
// succeed 1 time in 30. The generator accepts a layout only if both answers are
// unique from what is visible: the back shape hides nothing and every other
// shape hides part of an earlier one; the front shape is hidden by nothing and
// every other shape is partly hidden by a later one.
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
		x, y, _ := labelPoint(masks, i)
		c.disc(x, y, 11, color3)
		c.digit(labels[i]+1, x-4, y-7, 7, 2, paperInk)
	}
	c.noise(r, 5)
	url, err := c.dataURL()
	if err != nil {
		return Public{}, Answer{}, err
	}
	return Public{Family: StackOrder, Images: []string{url}, Options: stackShapes, Markers: 2},
		Answer{Family: StackOrder, Values: []int{labels[0], labels[stackShapes-1]}}, nil
}

// stackLayout places the shapes on a ring, so that each overlaps only its two
// neighbours. The drawing order rises from the back shape to the front shape
// along both arcs of the ring, interleaved at random. Then every shape except the
// back one covers an earlier neighbour, and every shape except the front one is
// covered by a later neighbour, which makes both answers unique by construction.
// stackValid still checks each layout, including that every shape stays visible.
func stackLayout(r *rand.Rand) ([][][2]float64, [][]bool) {
	n := stackShapes
	start := r.Float64() * 2 * math.Pi
	centres := make([][2]float64, n)
	for k := range n {
		a := start + 2*math.Pi*float64(k)/float64(n) + (r.Float64()-0.5)*0.25
		centres[k] = [2]float64{stackW/2 + math.Cos(a)*90, stackH/2 + math.Sin(a)*58}
	}
	back := r.IntN(n)
	front := (back + 2 + r.IntN(n-3)) % n
	var arcA, arcB []int
	for k := (back + 1) % n; k != front; k = (k + 1) % n {
		arcA = append(arcA, k)
	}
	for k := (back + n - 1) % n; k != front; k = (k + n - 1) % n {
		arcB = append(arcB, k)
	}
	order := []int{back}
	for len(arcA) > 0 || len(arcB) > 0 {
		if len(arcB) == 0 || (len(arcA) > 0 && r.IntN(2) == 0) {
			order, arcA = append(order, arcA[0]), arcA[1:]
		} else {
			order, arcB = append(order, arcB[0]), arcB[1:]
		}
	}
	order = append(order, front)

	shapes := make([][][2]float64, n)
	masks := make([][]bool, n)
	for i, pos := range order {
		cx, cy := centres[pos][0], centres[pos][1]
		radius := 62 + r.Float64()*6
		vertices := 5 + r.IntN(3)
		pts := make([][2]float64, vertices)
		for k := range vertices {
			a := 2 * math.Pi * (float64(k) + r.Float64()*0.6) / float64(vertices)
			rr := radius * (0.8 + r.Float64()*0.2)
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
	// Every shape but the front one must be partly covered by a later shape.
	for i := 0; i < len(masks)-1; i++ {
		covered := false
		for j := i + 1; j < len(masks); j++ {
			if overlap(masks[i], masks[j]) >= minOverlap {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	for i := range masks {
		if visible(masks, i) < minVisible {
			return false
		}
		if _, _, clearance := labelPoint(masks, i); clearance < minClearance {
			return false
		}
	}
	return true
}

// labelPoint finds a visible point of shape i far from any edge, for its number.
func labelPoint(masks [][]bool, i int) (float64, float64, int) {
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
	return float64(bestX), float64(bestY), best
}
