// Copyright (c) 2025 Karl Gaissmaier
// SPDX-License-Identifier: MIT

// Package value provides runtime utilities for working with generic type
// parameters as payload values in bart data structures.
//
// The package offers three main categories of utilities:
//
// # Zero-Sized Type (ZST) Detection
//
// IsZST[V] detects whether a type parameter V is a zero-sized type (such as
// struct{} or [0]byte). This serves two purposes:
//   - Runtime validation: Fast[V] cannot work correctly with zero-sized types
//     and must reject them. PanicOnZST enables a safety check that panics
//     during Fast.Insert and Fast.InsertPersist operations.
//   - Debug output clarity: Zero-sized types carry no information in their
//     values. Omitting them from dumps and prints reduces line noise and
//     improves readability.
//
// # Value Equality
//
// The Equaler[V] interface and Equal function enable custom equality logic
// for payload values. When V implements Equaler[V], the Equal function uses
// that implementation, avoiding the potentially expensive reflect.DeepEqual.
//
// # Value Cloning
//
// The Cloner[V] interface and associated functions (CloneFnFactory, CloneVal,
// CopyVal) support deep copying of payload values for persistent operations.
// When V implements Cloner[V], bart methods like InsertPersist, DeletePersist,
// and UnionPersist use the Clone method to create independent copies.
//
// This is an internal package used by the bart data structure implementation.
package value

import (
	"fmt"
	"reflect"
)

// IsZST reports whether type V is a zero-sized type (ZST).
//
// Zero-sized types such as struct{}, [0]byte, or structs/arrays with no fields
// occupy no memory. The Go runtime optimizes allocations of ZSTs by returning
// pointers to the same memory address (typically runtime.zerobase).
//
// This function exploits that optimization: it allocates two instances of V
// and compares their addresses. If the addresses are equal, V must be a ZST,
// since distinct non-zero-sized allocations would have different addresses.
//
// The helper escapeToHeap ensures both allocations reach the heap and prevents
// the compiler from proving address equality at compile time, which would
// invalidate the runtime check.
func IsZST[V any]() bool {
	a, b := escapeToHeap[V]()
	return a == b
}

// escapeToHeap forces two allocations of type V to escape to the heap.
//
// The go:noinline directive is critical: it prevents the compiler from inlining
// this function and optimizing away the allocations or proving that a == b at
// compile time. Without it, the compiler could elide one allocation or determine
// the result statically, breaking the ZST detection heuristic.
//
//go:noinline
func escapeToHeap[V any]() (*V, *V) {
	return new(V), new(V)
}

// PanicOnZST panics if V is a zero sized type.
// bart.Fast must reject zero-sized types as payload.
func PanicOnZST[V any]() {
	if IsZST[V]() {
		panic(fmt.Errorf("%T is a zero-sized type, not allowed as payload for bart.Fast", *new(V)))
	}
}

// Equaler is a generic interface for types that can decide their own
// equality logic. It can be used to override the potentially expensive
// default comparison with [reflect.DeepEqual].
type Equaler[V any] interface {
	Equal(other V) bool
}

// Equal compares two values of type V for equality.
// If V implements Equaler[V], that custom equality method is used,
// avoiding the potentially expensive reflect.DeepEqual.
// Otherwise, reflect.DeepEqual is used as a fallback.
func Equal[V any](v1, v2 V) bool {
	// you can't assert directly on a type parameter
	if v1, ok := any(v1).(Equaler[V]); ok {
		return v1.Equal(v2)
	}
	// fallback
	return reflect.DeepEqual(v1, v2)
}

// Cloner is an interface that enables deep cloning of values of type V.
// If a value implements Cloner[V], Table methods such as InsertPersist,
// ModifyPersist, DeletePersist, UnionPersist, Union and Clone will use
// its Clone method to perform deep copies.
type Cloner[V any] interface {
	Clone() V
}

// CloneFunc is a type definition for a function that takes a value of type V
// and returns the (possibly cloned) value of type V.
type CloneFunc[V any] func(V) V

// CloneFnFactory returns a CloneFunc.
// If V implements Cloner[V], the returned function should perform
// a deep copy using Clone(), otherwise it returns nil.
func CloneFnFactory[V any]() CloneFunc[V] {
	var zero V
	// you can't assert directly on a type parameter
	if _, ok := any(zero).(Cloner[V]); ok {
		return CloneVal[V]
	}
	return nil
}

// CloneVal returns a deep clone of val by calling Clone when
// val implements Cloner[V]. If val does not implement
// Cloner[V] or the Cloner receiver is nil (val is a nil pointer),
// CloneVal returns val unchanged.
func CloneVal[V any](val V) V {
	// you can't assert directly on a type parameter
	c, ok := any(val).(Cloner[V])
	if !ok || c == nil {
		return val
	}
	return c.Clone()
}

// CopyVal just copies the value of any type V.
func CopyVal[V any](val V) V {
	return val
}
