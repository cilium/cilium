// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iterator

// VecIterator is an iterator that returns a vector of elements of type T for
// each iteration.
type VecIterator[T any] interface {
	// Reset resets the iterator to its initial state.
	Reset()

	// Next returns the next vector of elements of type T and true if there is a value left
	// and false otherwise.
	Next() ([]T, bool)

	// ForEach iterates over all the vectors in the iterator.
	ForEach(func([]T))

	// Size of returned vectors
	vecn() int //nolint:unused // false positive, used in product(...).

	// Raw size of underlying data, used for allocation purposes internally.
	size() int //nolint:unused // false positive, used in product(...).
}

// implements VecIterator on a single contiguous slice of elements of type T.
type vecIterator[T any] struct {
	d []T
	i int
	n int // size of vectors in iterator
}

func (i *vecIterator[T]) Reset() {
	i.i = 0
}

func (i *vecIterator[T]) Next() ([]T, bool) {
	index := i.i
	if index >= len(i.d) {
		return nil, false
	}

	r := i.d[index : index+i.n]
	i.i += i.n
	return r, true
}

func (i *vecIterator[T]) size() int {
	return len(i.d)
}

func (i *vecIterator[T]) vecn() int {
	return i.n
}
func (i *vecIterator[T]) ForEach(fn func([]T)) {
	for {
		us, ok := i.Next()
		if !ok {
			break
		}
		fn(us)
	}
	i.Reset()
}

// Vec1 initializes a VecIterator where the size n of the vectors is 1.
func Vec1[T any](d []T) *vecIterator[T] {
	return &vecIterator[T]{
		d: d,
		i: 0,
		n: 1,
	}
}
