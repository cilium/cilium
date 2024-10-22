// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index

import (
	"fmt"
	"iter"
)

func String(s string) Key {
	return []byte(s)
}

func Stringer[T fmt.Stringer](s T) Key {
	return String(s.String())
}

func StringSlice(ss []string) KeySet {
	keys := make([]Key, 0, len(ss))
	for _, s := range ss {
		keys = append(keys, String(s))
	}
	return NewKeySet(keys...)
}

func StringerSlice[T fmt.Stringer](ss []T) KeySet {
	keys := make([]Key, 0, len(ss))
	for _, s := range ss {
		keys = append(keys, Stringer(s))
	}
	return NewKeySet(keys...)
}

func StringerSeq[T fmt.Stringer](seq iter.Seq[T]) KeySet {
	return Seq[T](Stringer, seq)
}

func StringerSeq2[A fmt.Stringer, B any](seq iter.Seq2[A, B]) KeySet {
	return Seq2[A, B](Stringer, seq)
}
