// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iterator

// CartesianProduct computes the cartesian product of the given iterators, going
// from left to right.
// The returned iterator provides the final computed vectors.
func CartesianProduct[T any](vs ...VecIterator[T]) VecIterator[T] {
	if len(vs) == 0 {
		return nil
	}

	if len(vs) == 1 {
		return vs[0]
	}

	lhs := vs[0]
	for i := 1; i < len(vs); i++ {
		rhs := vs[i]
		lhs = product(lhs, rhs)
	}

	return lhs
}

func product[T any](a VecIterator[T], b VecIterator[T]) VecIterator[T] {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	defer func() {
		a.Reset()
		b.Reset()
	}()
	p := make([]T, 0, a.size()*b.size())
outer:
	for {
		us, ok := a.Next()
		if !ok {
			break outer
		}
	inner:
		for {
			vs, ok := b.Next()
			if !ok {
				b.Reset()
				break inner
			}
			p = append(p, us...)
			p = append(p, vs...)
		}
	}
	return &vecIterator[T]{
		d: p,
		i: 0,
		n: a.vecn() + 1,
	}
}
