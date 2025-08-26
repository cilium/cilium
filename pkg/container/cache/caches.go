// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"maps"

	"github.com/cespare/xxhash/v2"
)

var (
	Strings = New(
		xxhash.Sum64String,
		func(s string) bool {
			// Skip caching of long strings
			return len(s) > 256
		},
		func(a, b string) bool { return a == b },
	)

	StringMaps = New(
		func(m map[string]string) (hash uint64) {
			for k, v := range m {
				// Dedup the strings
				_, hashk := Strings.getWithHash(k)
				_, hashv := Strings.getWithHash(v)
				hash = hash ^ hashk ^ hashv
			}
			return
		},
		func(m map[string]string) bool {
			// Skip caching of large maps
			return len(m) > 32
		},
		maps.Equal,
	)
)
