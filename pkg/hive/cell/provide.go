// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"

	"go.uber.org/dig"

	"github.com/cilium/cilium/pkg/hive/internal"
)

// provider is a set of constructors
type provider struct {
	ctors []any
}

func (p *provider) Apply(c container) error {
	for _, ctor := range p.ctors {
		if err := c.Provide(ctor, dig.Export(true)); err != nil {
			return err
		}
	}
	return nil
}

func (p *provider) String() string {
	var out string
	for _, ctor := range p.ctors {
		out += fmt.Sprintf("🚧️ %s: %T\n", internal.FuncNameAndLocation(ctor), ctor)
	}
	return out
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
