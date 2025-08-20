// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bitlpm

import (
	"fmt"
	"testing"
)

func mask(v, bitcnt uint8) uint8 {
	m := ^(^uint8(0) >> bitcnt)
	return v & m
}

func FuzzUint8(f *testing.F) {
	// has the fuzzing engine generate a set of []uint8, which it interprets as
	// a sequence of (val, prefixlen) pairs.

	// Then, checks invariants

	f.Add([]byte{0b1111_1111, 4})

	f.Fuzz(func(t *testing.T, sequence []byte) {

		type testEntry struct {
			k    uint8
			plen uint8
			val  uint16 // a placeholder
		}

		tree := NewUintTrie[uint8, testEntry]()

		seen := map[string]testEntry{}

		// Insert every item in to the tree, recording the prefix in to a hash as well
		// so we know what we've set
		for i := 0; i < len(sequence)-1; i += 2 {
			k := sequence[i]
			prefixLen := sequence[i+1] % 8

			seenk := fmt.Sprintf("%#b/%d", mask(k, prefixLen), prefixLen)

			seen[seenk] = testEntry{
				k:    k,
				plen: prefixLen,
				val:  uint16(k)<<8 + uint16(prefixLen),
			}

			tree.Upsert(uint(prefixLen), k, seen[seenk]) // may overwrite

		}

		if tree.Len() != uint(len(seen)) {
			t.Errorf("unexpected length: %d (expected %d)", tree.Len(), len(seen))
		}

		// Now, validate
		for seenK, seenV := range seen {
			var val testEntry
			tree.Ancestors(uint(seenV.plen), seenV.k, func(_ uint, _ uint8, v testEntry) bool {
				val = v
				return true
			})
			if val.val != seenV.val {
				t.Errorf("seenKey %s: got val %#b expected %#b", seenK, val.val, seenV.val)
			}
		}

		// Now, delete seen keys and validate
		expectedLength := len(seen)
		for seenK, seenV := range seen {
			t.Logf("Deleting key %s", seenK)
			tree.Delete(uint(seenV.plen), seenV.k)
			expectedLength--

			if tree.Len() != uint(expectedLength) {
				t.Errorf("unexpected length: %d (expected %d)", tree.Len(), expectedLength)
			}
		}
	})
}
