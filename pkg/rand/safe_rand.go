// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rand

import (
	"math/rand"

	"github.com/cilium/cilium/pkg/lock"
)

// safeRand is a concurrency-safe source of pseudo-random numbers. The Go
// stdlib's math/rand.Source is not concurrency-safe. The global source in
// math/rand would be concurrency safe (due to its internal use of
// lockedSource), but it is prone to inter-package interference with the PRNG
// state.
// Also see https://github.com/cilium/cilium/issues/10988
type safeRand struct {
	mu lock.Mutex
	r  *rand.Rand
}

func NewSafeRand(seed int64) safeRand {
	return safeRand{r: rand.New(rand.NewSource(seed))}
}

func (sr *safeRand) Seed(seed int64) {
	sr.mu.Lock()
	sr.r.Seed(seed)
	sr.mu.Unlock()
}

func (sr *safeRand) Int63() int64 {
	sr.mu.Lock()
	v := sr.r.Int63()
	sr.mu.Unlock()
	return v
}

func (sr *safeRand) Int63n(n int64) int64 {
	sr.mu.Lock()
	v := sr.r.Int63n(n)
	sr.mu.Unlock()
	return v
}

func (sr *safeRand) Uint32() uint32 {
	sr.mu.Lock()
	v := sr.r.Uint32()
	sr.mu.Unlock()
	return v
}

func (sr *safeRand) Uint64() uint64 {
	sr.mu.Lock()
	v := sr.r.Uint64()
	sr.mu.Unlock()
	return v
}

func (sr *safeRand) Intn(n int) int {
	sr.mu.Lock()
	v := sr.r.Intn(n)
	sr.mu.Unlock()
	return v
}

func (sr *safeRand) Float64() float64 {
	sr.mu.Lock()
	v := sr.r.Float64()
	sr.mu.Unlock()
	return v
}

func (sr *safeRand) Perm(n int) []int {
	sr.mu.Lock()
	v := sr.r.Perm(n)
	sr.mu.Unlock()
	return v

}

func (sr *safeRand) Shuffle(n int, swap func(i, j int)) {
	sr.mu.Lock()
	sr.r.Shuffle(n, swap)
	sr.mu.Unlock()
}
