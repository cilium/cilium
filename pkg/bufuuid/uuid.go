// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bufuuid

import (
	"bufio"
	"crypto/rand"
	"io"

	"github.com/google/uuid"

	"github.com/cilium/cilium/pkg/lock"
)

// Generator provides thread-safe convenience methods to generate random v4 UUIDs,
// leveraging a buffer to amortize the cost of reading from the random source.
type Generator struct {
	mu     lock.Mutex
	rander io.Reader
}

// New returns a new object that can be used to generate random v4 UUID instances,
// analogously to "github.com/google/uuid".New(). It leverages an internal buffer
// (via a thread-safe bufio.Reader) to amortize the cost of reading from the random
// source when generating a large number of UUIDs. This behavior is similar to
// "github.com/google/uuid".EnableRandPool, but confined to this specific generator
// instance, so that it can be used when security is not a concern (i.e., it is not
// a problem that the buffer is stored on the Go heap), without needing to enable
// it globally. In addition, the generator provides a NewInto method that does not
// cause allocations (opposed to "github.com/google/uuid".NewRandomFromReader()).
func New() *Generator {
	// The default number of slots has been selected based on BenchmarkUUIDGenerator
	// considering that the amount of memory overhead is negligible (1024B).
	//
	// goos: linux
	// goarch: amd64
	// pkg: github.com/cilium/cilium/pkg/bufuuid
	// cpu: 13th Gen Intel(R) Core(TM) i7-13800H
	// BenchmarkUUIDGenerator/1_slots-20                3601372               320.7 ns/op             0 B/op          0 allocs/op
	// BenchmarkUUIDGenerator/2_slots-20                7033866               170.5 ns/op             0 B/op          0 allocs/op
	// BenchmarkUUIDGenerator/4_slots-20                9879603               120.2 ns/op             0 B/op          0 allocs/op
	// BenchmarkUUIDGenerator/8_slots-20               14407450                82.39 ns/op            0 B/op          0 allocs/op
	// BenchmarkUUIDGenerator/16_slots-20              18318152                64.33 ns/op            0 B/op          0 allocs/op
	// BenchmarkUUIDGenerator/32_slots-20              22014920                55.26 ns/op            0 B/op          0 allocs/op
	// BenchmarkUUIDGenerator/64_slots-20              24211341                49.36 ns/op            0 B/op          0 allocs/op
	// BenchmarkUUIDGenerator/128_slots-20             24080565                48.26 ns/op            0 B/op          0 allocs/op
	// BenchmarkUUIDGenerator/256_slots-20             25684521                45.80 ns/op            0 B/op          0 allocs/op
	const slots = 64
	return newWith(rand.Reader, slots)
}

func newWith(rander io.Reader, slots uint64) *Generator {
	return &Generator{
		rander: bufio.NewReaderSize(rander, int(slots)*len(uuid.UUID{})),
	}
}

// New creates a new random UUID or panics.
func (g *Generator) New() uuid.UUID {
	var u uuid.UUID
	g.NewInto(&u)
	return u
}

// NewInto writes a new random UUID into target, or panics.
func (g *Generator) NewInto(target *uuid.UUID) {
	g.mu.Lock()

	_, err := io.ReadFull(g.rander, target[:])
	if err != nil {
		g.mu.Unlock()
		panic(err)
	}

	g.mu.Unlock()

	target[6] = (target[6] & 0x0f) | 0x40 // Version 4
	target[8] = (target[8] & 0x3f) | 0x80 // Variant is 10
}
