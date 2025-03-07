//go:build !go1.22

package rand

import "math/rand"

func Shuffle(n int, swap func(i, j int)) {
	rand.Shuffle(n, swap)
}

func IntN(n int) int {
	// bearer:disable go_gosec_crypto_weak_random
	return rand.Intn(n)
}
