// Copyright 2019 Authors of Cilium
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

package lbmap

import (
	lb "github.com/cilium/cilium/pkg/loadbalancer"
)

const (
	// HashSeed0 is seed0 for maglev hash
	HashSeed0 = uint32(0)

	// HashSeed1 is seed3 for maglev hash
	HashSeed1 = uint32(2307)

	// HashSeed2 is seed3 for maglev hash
	HashSeed2 = uint64(42)

	// HashSeed3 is seed3 for maglev hash
	HashSeed3 = uint64(2718281828)
)

func rotl64(x uint64, r uint8) uint64 {
	return (x << r) | (x >> (64 - r))
}

func murmurHash3x64_64(A uint64, B uint64, seed uint32) uint64 {
	h1 := uint64(seed)
	h2 := uint64(seed)

	c1 := uint64(0x87c37b91114253d5)
	c2 := uint64(0x4cf5ad432745937f)

	// body

	k1 := A
	k2 := B

	k1 *= c1
	k1 = rotl64(k1, 31)
	k1 *= c2
	h1 ^= k1

	h1 = rotl64(h1, 27)
	h1 += h2
	h1 = h1*5 + 0x52dce729

	k2 *= c2
	k2 = rotl64(k2, 33)
	k2 *= c1
	h2 ^= k2

	h2 = rotl64(h2, 31)
	h2 += h1
	h2 = h2*5 + 0x38495ab5

	// finalization

	h1 ^= 16
	h2 ^= 16

	h1 += h2
	h2 += h1

	h1 ^= h1 >> 33
	h1 *= uint64(0xff51afd7ed558ccd)
	h1 ^= h1 >> 33
	h1 *= uint64(0xc4ceb9fe1a85ec53)
	h1 ^= h1 >> 33

	h2 ^= h2 >> 33
	h2 *= uint64(0xff51afd7ed558ccd)
	h2 ^= h2 >> 33
	h2 *= uint64(0xc4ceb9fe1a85ec53)
	h2 ^= h2 >> 33

	h1 += h2

	return h1
}

func genMaglevPermuation(permutation []uint32, hash uint64, i int, ringSize uint64) {
	//offset
	permutation[2*i] = uint32(murmurHash3x64_64(hash, HashSeed2, HashSeed0) % ringSize)
	//skip
	permutation[2*i+1] = uint32((murmurHash3x64_64(hash, HashSeed3, HashSeed1) % (ringSize - 1)) + 1)
}

func generateMaglevHash(backends []*lb.BackendMeta, ringSize uint32) lb.MaglevRing {
	blen := len(backends)
	ring := lb.NewMaglevRing(int(ringSize), -1)
	if blen == 0 {
		return ring
	}
	if blen == 1 {
		id := int(backends[0].ID)
		for i := 0; i < len(ring); i++ {
			ring[i] = id
		}
		return ring
	}

	runs := uint32(0)
	permutation := make([]uint32, blen*2)
	next := make([]uint32, blen)

	for i, backend := range backends {
		genMaglevPermuation(permutation, backend.Hash, i, uint64(ringSize))
	}

	for {
		for i, backend := range backends {
			offset := permutation[2*i]
			skip := permutation[2*i+1]
			// our realization of "weights" for maglev's hash.
			for j := uint32(0); j < backend.Weight; j++ {
				cur := (offset + next[i]*skip) % ringSize
				for ring[cur] >= 0 {
					next[i] += 1
					cur = (offset + next[i]*skip) % ringSize
				}
				ring[cur] = int(backend.ID)
				next[i] += 1
				runs++
				if runs == ringSize {
					return ring
				}
			}
			backend.Weight = 1
		}
	}
}
