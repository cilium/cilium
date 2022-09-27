// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"github.com/spf13/pflag"
	"go.uber.org/dig"
	"go.uber.org/fx"
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
	RegisterFlags(*pflag.FlagSet)
	ToOption(settings map[string]any) (fx.Option, error)
}

// In when embedded into a struct used as constructor parameter makes the exported
// values of that struct become dependency injected values. In other words, it allows
// moving a long list of constructor parameters into a struct.
//
// Struct fields can be annotated with `optional:"true"` to make the dependency optional.
// If the type is not found in the dependency graph, the value is set to the zero value.
//
// See https://pkg.go.dev/go.uber.org/dig#In for more information.
type In = fx.In

// Out when embedded into a struct that is returned by a constructor will make the
// values in the struct become objects in the dependency graph instead of the struct
// itself.
//
// See https://pkg.go.dev/go.uber.org/dig#Out for more information.
type Out = dig.Out

// provider is a named cell for a set of constructors
type provider struct {
	name  string
	ctors []any
}

func (c *provider) RegisterFlags(flags *pflag.FlagSet) {
}

func (c *provider) ToOption(settings map[string]any) (fx.Option, error) {
	return fx.Module(c.name, fx.Provide(c.ctors...)), nil
}

// Provide constructs a new named cell with the given name and constructors.
// Constructor is any function that takes zero or more parameters and returns
// one or more values and optionally an error. For example, the following forms
// are accepted:
//
//	func() A
//	func(A, B, C) (D, error).
//
// If the constructor depends on a type that is not provided by any constructor
// the hive will fail to run with an error pointing at the missing type.
//
// A constructor can also take as parameter a structure of parameters annotated
// with `cell.In`, or return a struct annotated with `cell.Out`:
//
//	type params struct {
//		cell.In
//		Flower *Flower
//		Sun *Sun
//	}
//
//	type out struct {
//		cell.Out
//		Honey *Honey
//		Nectar *Nectar
//	}
//
//	func newBee(params) (out, error)
func Provide(ctors ...any) Cell {
	return &provider{ctors: ctors}
}

// module is a named set of cells.
type module struct {
	name  string
	cells []Cell
}

// Module creates a named set of cells.
// The name will be included in the object dump (hive.PrintObjects) and
// in the dot graph (hive.PrintDotGraph).
func Module(name string, cells ...Cell) Cell {
	return &module{name, cells}
}

func (g *module) RegisterFlags(flags *pflag.FlagSet) {
	for _, cell := range g.cells {
		cell.RegisterFlags(flags)
	}
}

func (g *module) ToOption(settings map[string]any) (fx.Option, error) {
	opts := []fx.Option{}
	for _, cell := range g.cells {
		opt, err := cell.ToOption(settings)
		if err != nil {
			return nil, err
		}
		opts = append(opts, opt)
	}
	return fx.Module(g.name, opts...), nil
}
