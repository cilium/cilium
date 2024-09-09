// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index

import "github.com/cilium/statedb/part"

// Set creates a KeySet from a part.Set.
func Set[T any](s part.Set[T]) KeySet {
	toBytes := s.ToBytesFunc()
	switch s.Len() {
	case 0:
		return NewKeySet()
	case 1:
		for v := range s.All() {
			return NewKeySet(toBytes(v))
		}
		panic("BUG: Set.Len() == 1, but ranging returned nothing")
	default:
		keys := make([]Key, 0, s.Len())
		for v := range s.All() {
			keys = append(keys, toBytes(v))
		}
		return NewKeySet(keys...)
	}
}
