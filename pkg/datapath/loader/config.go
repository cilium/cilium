// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"iter"

	"github.com/cilium/cilium/pkg/lock"
)

// funcRegistry is a thread-safe registry of functions.
type funcRegistry[T any] struct {
	mu    lock.Mutex
	funcs []T
}

// register is typically called in init() to register a function.
func (cf *funcRegistry[T]) register(f T) {
	cf.mu.Lock()
	defer cf.mu.Unlock()

	cf.funcs = append(cf.funcs, f)
}

// all returns an iterator over all registered functions.
func (cf *funcRegistry[T]) all() iter.Seq[T] {
	return func(yield func(T) bool) {
		cf.mu.Lock()
		defer cf.mu.Unlock()

		for _, f := range cf.funcs {
			if !yield(f) {
				return
			}
		}
	}
}
