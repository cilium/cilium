// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package maglev

import (
	"encoding/base64"
	"fmt"
	"runtime"
	"sync"

	"github.com/cilium/cilium/pkg/murmur3"
)

const (
	DefaultTableSize = 16381

	// seed=$(head -c12 /dev/urandom | base64 -w0)
	DefaultHashSeed = "JLfvgnHc2kaSUFaI"
)

var (
	seedMurmur uint32

	SeedJhash0 uint32
	SeedJhash1 uint32
)

func InitMaglevSeeds(seed string) error {
	d, err := base64.StdEncoding.DecodeString(seed)
	if err != nil {
		return fmt.Errorf("Cannot decode base64 Maglev hash seed %q: %w", seed, err)
	}
	if len(d) != 12 {
		return fmt.Errorf("Decoded hash seed is %d bytes (not 12 bytes)", len(d))
	}

	seedMurmur = uint32(d[0])<<24 | uint32(d[1])<<16 | uint32(d[2])<<8 | uint32(d[3])

	SeedJhash0 = uint32(d[4])<<24 | uint32(d[5])<<16 | uint32(d[6])<<8 | uint32(d[7])
	SeedJhash1 = uint32(d[8])<<24 | uint32(d[9])<<16 | uint32(d[10])<<8 | uint32(d[11])

	return nil
}

func getOffsetAndSkip(backend string, m uint64) (uint64, uint64) {
	h1, h2 := murmur3.Hash128([]byte(backend), seedMurmur)
	offset := h1 % m
	skip := (h2 % (m - 1)) + 1

	return offset, skip
}

func getPermutation(backends []string, m uint64, numCPU int) []uint64 {
	var wg sync.WaitGroup
	bCount := len(backends)
	perm := make([]uint64, bCount*int(m))

	// The idea is to split the calculation into batches so that they can be
	// concurrently executed.  We limit the number of concurrent goroutines to
	// the number of available CPU cores. This is because the calculation does
	// not block and is completely CPU-bound. Therefore, adding more goroutines
	// would result into an overhead (allocation of stackframes, stress on
	// scheduling, etc) instead of a performance gain.

	batchSize := bCount / numCPU
	if batchSize == 0 {
		batchSize = bCount
	}

	for g := 0; g < bCount; g += batchSize {
		wg.Add(1)
		go func(from int) {
			to := from + batchSize
			if to > bCount {
				to = bCount
			}
			for i := from; i < to; i++ {
				offset, skip := getOffsetAndSkip(backends[i], m)
				perm[i*int(m)] = offset % m
				for j := uint64(1); j < m; j++ {
					perm[i*int(m)+int(j)] = (perm[i*int(m)+int(j-1)] + skip) % m
				}

			}
			wg.Done()
		}(g)
	}
	wg.Wait()

	return perm
}

// GetLookupTable returns the Maglev lookup table of the size "m" for the given
// backends. The lookup table contains the indices of the given backends.
func GetLookupTable(backends []string, m uint64) []int {
	if len(backends) == 0 {
		return nil
	}

	perm := getPermutation(backends, m, runtime.NumCPU())
	next := make([]int, len(backends))
	entry := make([]int, m)

	for j := uint64(0); j < m; j++ {
		entry[j] = -1
	}

	l := len(backends)

	for n := uint64(0); n < m; n++ {
		i := int(n) % l
		c := perm[i*int(m)+next[i]]
		for entry[c] >= 0 {
			next[i] += 1
			c = perm[i*int(m)+next[i]]
		}
		entry[c] = i
		next[i] += 1
	}

	return entry
}
