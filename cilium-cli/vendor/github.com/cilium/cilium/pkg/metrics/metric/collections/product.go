// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package collections

// CartesianProduct returns the cartesian product of the input vectors as
// a vector of vectors, each with length the same as the number of input vectors.
func CartesianProduct[T any](vs ...[]T) [][]T {
	if len(vs) == 0 {
		return [][]T{}
	}

	dimension := len(vs) // Each output will be a vector of this length.
	// Iterate to find out the number of output vectors.
	size := len(vs[0])
	for i := 1; i < len(vs); i++ {
		size *= len(vs[i])
	}

	// Allocate the output vectors.
	dst := make([][]T, size)
	for i := range dst {
		dst[i] = make([]T, dimension)
	}

	lastm := 1
	for i := 0; i < dimension; i++ {
		permuteColumn[T](dst, i, lastm, vs[i])
		lastm = lastm * len(vs[i])
	}
	return dst
}

// permuteColumn fills in the nth column of the output vectors of the cartesian
// product of the input vectors.
//
// leftPermSize is the number of vectors as a result of permuting 0,..,col-1 columns.
// That is, this is the block size upon which we will repeat the values of v0 such that
// every previous permutation is again permuted with each value of v0.
//
// For ex.
// CartesianProduct[string]({"a", "b"}, {"x", "y", "z"})
//
// Iteration (i.e. col, leftPermSize=1) 1:
//
// dst = [
// ["a"],
// ["b"],
// ["a"]
// ["b"]
// ["a"]
// ["b"]
// ]
//
// Iteration (leftPermSize=2):
//
// dst = [
// ["a", "x"], // <- each elem of vec is repeated leftPermSize times.
// ["b", "x"],
// ["a", "y"]
// ["b", "y"]
// ["a", "z"]
// ["b", "z"]
// ]
func permuteColumn[T any](dst [][]T, col int, leftPermSize int, vec []T) {
	// Go down the column with the current lhs.
	// You want to skip along, lastm elements at a time.
	for i := 0; i < len(dst); i += leftPermSize { // So we're skipping n rows at a time,
		vi := (i / leftPermSize) % len(vec)
		for off := 0; off < leftPermSize; off++ { // this is a repeat
			dst[i+off][col] = vec[vi]
		}
	}
}
