// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import "fmt"

// This API was inspired by Rust's std::option.

// Optional represents an optional value of any type. It is used throughout the
// Hive to propagate values that may or may not be present at runtime, such as
// BPF maps that are only available when certain features are enabled.
//
// Call [Optional.Get] to retrieve the value along with a boolean indicating
// whether the boxed value was populated by the provider.
//
// Use [Some] and [None] to create Optional values.
type Optional[T any] struct {
	v    *T
	some bool
}

// Some returns an Optional containing the provided value.
func Some[T any](v T) Optional[T] {
	return Optional[T]{v: &v, some: true}
}

// None returns an empty Optional.
func None[T any]() Optional[T] {
	return Optional[T]{}
}

// Get returns the value contained in the Optional and a boolean indicating
// whether the value was set.
func (o Optional[T]) Get() (T, bool) {
	if !o.some {
		var zero T
		return zero, false
	}
	return *o.v, true
}

func (o Optional[T]) String() string {
	if o.some {
		return fmt.Sprintf("optional:%v", *o.v)
	}
	return "optional:none"
}
