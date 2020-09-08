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

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/sirupsen/logrus"
	"github.com/spaolacci/murmur3"
)

const (
	subsystem = "maglev"

	DefaultTableSize = 16381

	// seed=$(head -c16 /dev/urandom | base64 -w0)
	DefaultHashSeed = "FYJf2hrSynYxcZrkMWTGYA=="
)

var (
	seedMurmur0 uint32
	seedMurmur1 uint32

	SeedJhash0 uint32
	SeedJhash1 uint32
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsystem)

func InitMaglevSeeds() {
	d, err := base64.StdEncoding.DecodeString(option.Config.MaglevHashSeed)
	if err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.HashSeed: option.Config.MaglevHashSeed,
		}).Fatal("Cannot decode base64 Maglev hash seed.")
	}
	if len(d) != 16 {
		log.WithFields(logrus.Fields{
			logfields.HashSeed: option.Config.MaglevHashSeed,
		}).Fatal("Decoded Maglev hash seed is not 16 bytes.")
	}

	seedMurmur0 = uint32(d[0])<<24 | uint32(d[1])<<16 | uint32(d[2])<<8 | uint32(d[3])
	seedMurmur1 = uint32(d[4])<<24 | uint32(d[5])<<16 | uint32(d[6])<<8 | uint32(d[7])

	SeedJhash0 = uint32(d[8])<<24 | uint32(d[9])<<16 | uint32(d[10])<<8 | uint32(d[11])
	SeedJhash1 = uint32(d[12])<<24 | uint32(d[13])<<16 | uint32(d[14])<<8 | uint32(d[15])
}

func getOffsetAndSkip(backend string, m uint64) (uint64, uint64) {
	offset := murmur3.Sum64WithSeed([]byte(backend), seedMurmur0) % m
	skip := (murmur3.Sum64WithSeed([]byte(backend), seedMurmur1) % (m - 1)) + 1

	return offset, skip
}

func getPermutation(backends []string, m uint64) [][]uint64 {
	perm := make([][]uint64, len(backends))

	for i, backend := range backends {
		offset, skip := getOffsetAndSkip(backend, m)
		perm[i] = make([]uint64, m)
		perm[i][0] = offset % m
		for j := uint64(1); j < m; j++ {
			perm[i][j] = (perm[i][j-1] + skip) % m
		}
	}

	return perm
}

// GetLookupTable returns the Maglev lookup table of the size "m" for the given
// backends. The lookup table contains the indices of the given backends.
func GetLookupTable(backends []string, m uint64) []int {
	if len(backends) == 0 {
		return nil
	}

	perm := getPermutation(backends, m)
	next := make([]int, len(backends))
	entry := make([]int, m)

	for j := uint64(0); j < m; j++ {
		entry[j] = -1
	}
	n := uint64(0)

	for {
		for i := 0; i < len(backends); i++ {
			c := perm[i][next[i]]
			for entry[c] >= 0 {
				next[i] += 1
				c = perm[i][next[i]]
			}
			entry[c] = i
			next[i] += 1
			n += 1
			if n == m {
				return entry
			}
		}
	}
}
