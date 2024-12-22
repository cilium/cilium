package blackrock

import (
	"math"
)

// Blackrock cipher implementation from masscan

type BlackRock struct {
	Rounds int64
	Seed   int64
	Range  int64
	A      int64
	B      int64
}

func New(rangez, seed int64) *BlackRock {
	split := int64(math.Floor(math.Sqrt(float64(rangez))))
	var blackrock BlackRock
	blackrock.Rounds = 3
	blackrock.Seed = seed
	blackrock.Range = rangez
	blackrock.A = split - 1
	blackrock.B = split + 1

	if blackrock.A <= 0 {
		blackrock.A = 1
	}

	for blackrock.A*blackrock.B <= rangez {
		blackrock.B++
	}

	return &blackrock
}

// Inner permutation function
func (blackrock *BlackRock) F(j, r, seed int64) int64 {
	var primes = []int64{961752031, 982324657, 15485843, 961752031}
	r = (r << (r & 0x4)) + r + seed
	return int64(math.Abs(float64((((primes[j]*r + 25) ^ r) + j))))
}

// Outer feistal construction
func (blackrock *BlackRock) Fe(r, a, b, m, seed int64) int64 {
	var (
		L, R int64
		j    int64
		tmp  int64
	)

	L = m % a
	R = m / a

	for j = 1; j <= r; j++ {
		if j&1 == 1 {
			tmp = (L + blackrock.F(j, R, seed)) % a
		} else {
			tmp = (L + blackrock.F(j, R, seed)) % b
		}
		L = R
		R = tmp
	}

	if r&1 == 1 {
		return a*L + R
	}
	return a*R + L
}

// Outer reverse feistal construction
func (blackrock *BlackRock) Unfe(r, a, b, m, seed int64) int64 {
	var (
		L, R int64
		j    int64
		tmp  int64
	)

	if r&1 == 1 {
		R = m % a
		L = m / a
	} else {
		L = m % a
		R = m / a
	}

	for j = r; j >= 1; j-- {
		if j&1 == 1 {
			tmp = blackrock.F(j, L, seed)
			if tmp > R {
				tmp -= -R
				tmp = a - (tmp % a)
				if tmp == a {
					tmp = 0
				}
			} else {
				tmp = R - tmp
				tmp %= a
			}
		} else {
			tmp = blackrock.F(j, L, seed)
			if tmp > R {
				tmp = (tmp - R)
				tmp = b - (tmp % b)
				if tmp == b {
					tmp = 0
				}
			} else {
				tmp = R - tmp
				tmp %= b
			}
		}
		R = L
		L = tmp
	}

	return a*R + L
}

func (blackrock *BlackRock) Shuffle(m int64) int64 {
	c := blackrock.Fe(blackrock.Rounds, blackrock.A, blackrock.B, m, blackrock.Seed)

	for c >= blackrock.Range {
		c = blackrock.Fe(blackrock.Rounds, blackrock.A, blackrock.B, c, blackrock.Seed)
	}

	return c
}

func (blackrock *BlackRock) UnShuffle(m int64) int64 {
	c := blackrock.Unfe(blackrock.Rounds, blackrock.A, blackrock.B, m, blackrock.Seed)
	for c >= blackrock.Range {
		c = blackrock.Unfe(blackrock.Rounds, blackrock.A, blackrock.B, c, blackrock.Seed)
	}

	return c
}
