package pow

import "math"

// MaxBoost caps adaptive difficulty at 2^4 = 16 times the configured work.
const MaxBoost = 4.0

// Boost returns the extra work, in doublings, for the current load. It follows
// the log-scale approach of Private Captcha: difficulty grows slowly at first and
// is capped, so that shared addresses and traffic spikes are not punished hard.
//
// excessClient is how many challenges this address requested above its allowance
// in the current minute. siteRate and siteBaseline are the site's challenges per
// minute and its normal rate; a baseline of 0 ignores the site part.
func Boost(excessClient, siteRate, siteBaseline int64, growth float64) float64 {
	d := 0.0
	if excessClient > 0 {
		d += math.Log2(1 + float64(excessClient)/8)
	}
	if siteBaseline > 0 && siteRate > siteBaseline {
		d += math.Log2(1 + float64(siteRate-siteBaseline)/float64(4*siteBaseline))
	}
	return math.Min(MaxBoost, growth*d)
}

// Scale multiplies the expected work of a level by 2^boost. Whole doublings add
// bits and the remainder scales the count, which keeps the work smooth.
func Scale(bits, count int, boost float64) (int, int) {
	if boost <= 0 {
		return bits, count
	}
	whole := math.Floor(boost)
	bits += int(whole)
	count = int(math.Round(float64(count) * math.Pow(2, boost-whole)))
	for count > MaxCount && bits < MaxBits {
		bits++
		count = (count + 1) / 2
	}
	return min(bits, MaxBits), min(count, MaxCount)
}
