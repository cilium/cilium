package datapath

import (
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"golang.org/x/exp/constraints"
	"golang.org/x/exp/slices"
)

func newIDIndex[T any](getID func(T) ID) statedb.Index[T, ID] {
	return statedb.Index[T, ID]{
		Name: "id",
		FromObject: func(x T) index.KeySet {
			return index.NewKeySet(index.Uint64(uint64(getID(x))))
		},
		FromKey: func(id ID) index.Key {
			return index.Uint64(uint64(id))
		},
		Unique: true,
	}
}

// ImmSet is an immutable set optimized for a smallish set of items.
// Implemented as a sorted slice.
type ImmSet[T constraints.Ordered] []T

func NewImmSet[T constraints.Ordered](items ...T) ImmSet[T] {
	s := ImmSet[T](items)
	slices.Sort(s)
	return s
}

func (s ImmSet[T]) Has(x T) bool {
	_, found := slices.BinarySearch(s, x)
	return found
}

func (s ImmSet[T]) Insert(x T) ImmSet[T] {
	idx, found := slices.BinarySearch(s, x)
	if found {
		return s
	}
	return slices.Insert(slices.Clone(s), idx, x)
}

func (s ImmSet[T]) Delete(x T) ImmSet[T] {
	idx, found := slices.BinarySearch(s, x)
	if found {
		return slices.Delete(slices.Clone(s), idx, idx+1)
	}
	return s
}

func (s ImmSet[T]) Union(s2 ImmSet[T]) ImmSet[T] {
	result := make(ImmSet[T], 0, len(s)+len(s2))
	copy(result, s)
	copy(result[len(s):], s2)
	slices.Sort(result)
	return result
}

func (s ImmSet[T]) Difference(s2 ImmSet[T]) ImmSet[T] {
	result := ImmSet[T]{}
	for _, x := range s {
		if !s2.Has(x) {
			result = result.Insert(x)
		}
	}
	return result
}
