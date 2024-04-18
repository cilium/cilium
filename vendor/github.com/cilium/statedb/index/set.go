// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index

import "github.com/cilium/statedb/part"

// Set creates a KeySet from a part.Set.
func Set[T any](s part.Set[T]) KeySet {
	iter := s.All()
	toBytes := s.ToBytesFunc()

	switch s.Len() {
	case 0:
		return NewKeySet()
	case 1:
		v, _ := iter.Next()
		return NewKeySet(toBytes(v))

	default:
		keys := make([]Key, 0, s.Len())
		for v, ok := iter.Next(); ok; v, ok = iter.Next() {
			keys = append(keys, toBytes(v))
		}
		return NewKeySet(keys...)
	}
}
