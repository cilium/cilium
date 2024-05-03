// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"go.uber.org/dig"
)

// Cell is the modular building block of the hive.
//
// A cell can be constructed with:
//
//   - Module(): Create a named set of cells.
//   - Provide(): Provide object constructors.
//   - Invoke(): Invoke a function to instantiate objects.
//   - Decorate(): Decorate a set of cells to augment an object.
//   - Config(): Cell providing a configuration struct.
type Cell interface {
	// Info provides a structural summary of the cell for printing purposes.
	Info(container) Info

	// Apply the cell to the dependency graph container.
	Apply(container) error
}

// In when embedded into a struct used as constructor parameter makes the exported
// values of that struct become dependency injected values. In other words, it allows
// moving a long list of constructor parameters into a struct.
//
// Struct fields can be annotated with `optional:"true"` to make the dependency optional.
// If the type is not found in the dependency graph, the value is set to the zero value.
//
// See https://pkg.go.dev/go.uber.org/dig#In for more information.
type In = dig.In

// Out when embedded into a struct that is returned by a constructor will make the
// values in the struct become objects in the dependency graph instead of the struct
// itself.
//
// See https://pkg.go.dev/go.uber.org/dig#Out for more information.
type Out = dig.Out

// container is the common interface between dig.Container and dig.Scope.
// Used in Apply().
type container interface {
	Provide(ctor any, opts ...dig.ProvideOption) error
	Invoke(fn any, opts ...dig.InvokeOption) error
	Decorate(fn any, opts ...dig.DecorateOption) error
	Scope(name string, opts ...dig.ScopeOption) *dig.Scope
}
