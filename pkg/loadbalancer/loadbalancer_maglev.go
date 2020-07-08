// Copyright 2016-2017 Authors of Cilium
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

package loadbalancer

import "hash/fnv"

// BackendMaglev represents maglev info of backend.
type BackendMaglev struct {
	Hash   uint64
	Weight uint32
}

func (b *Backend) NewMaglev(weight uint32) *BackendMaglev {
	hasher := fnv.New64()
	_, _ = hasher.Write([]byte(b.String()))
	hash := hasher.Sum64() // FIXME: replace this with a better hash algorithm
	return &BackendMaglev{
		Hash:   hash,
		Weight: weight,
	}
}

// MaglevRing represents maglev hash ring.
type MaglevRing []int

// NewMaglevRing returns maglev ring which elems has been initialize to -1
func NewMaglevRing(ringSize, init int) MaglevRing {
	ring := make(MaglevRing, ringSize)
	for i := range ring {
		ring[i] = init
	}
	return ring
}

// MaglevElem represents maglev hash elem.
type MaglevElem struct {
	Key   uint32
	Value int32
}
