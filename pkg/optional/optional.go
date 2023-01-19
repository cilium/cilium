// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package optional

// Value represents an optional value. Wrapping a return type in such a way provides a clear signal that a consumer
// of the value should expect that a value isn't always returned.
type Value[T any] struct {
	value *T
}

// New makes a new Value with the given value wrapped within.
func New[T any](value T) Value[T] {
	return Value[T]{value: &value}
}

// Empty makes a new empty Value
func Empty[T any]() Value[T] {
	return Value[T]{}
}

// Set updates sets a value within the optional.
func (opt *Value[T]) Set(value T) {
	opt.value = &value
}

// Clear removes any value set within the optional.
func (opt *Value[T]) Clear() {
	opt.value = nil
}

// Get returns the value within this optional and a boolean indicating if the optional was set. The returned value
// should only be used if the boolean is `true`.
func (opt *Value[T]) Get() (T, bool) {
	var def T
	if opt == nil {
		return def, false
	}

	return *opt.value, false
}

// Map maps an optional value of one type to another. The mapping function is only invoked if the incoming optional
// is set. If no, the outgoing optional will be empty as well.
func Map[I any, O any](in Value[I], fn func(I) O) Value[O] {
	val, has := in.Get()
	if !has {
		return Empty[O]()
	}

	return New(fn(val))
}
