// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index

import "iter"

// Seq creates a KeySet from an iter.Seq[T] with the given indexing function.
// Example usage:
//
//	var strings iter.Seq[string]
//	keys := Seq[string](index.String, strings)
func Seq[T any](
	toKey func(T) Key,
	seq iter.Seq[T],
) KeySet {
	keys := []Key{}
	for v := range seq {
		keys = append(keys, toKey(v))
	}
	return NewKeySet(keys...)
}

// Seq2 creates a KeySet from an iter.Seq2[A,B] with the given indexing function.
// Example usage:
//
//	 var seq iter.Seq2[string, int]
//		keys := Seq2(index.String, seq)
func Seq2[A, B any](
	toKey func(A) Key,
	seq iter.Seq2[A, B],
) KeySet {
	keys := []Key{}
	for a := range seq {
		keys = append(keys, toKey(a))
	}
	return NewKeySet(keys...)
}
