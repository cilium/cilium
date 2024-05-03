// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"

	"github.com/cilium/hive/internal"
)

// Decorate takes a decorator function and a set of cells and returns
// a decorator cell.
//
// A decorator function is a function that takes as arguments objects
// in the hive and returns one or more augmented objects. The cells wrapped
// with a decorator will be provided the returned augmented objects.
//
// Example:
//
//	cell.Decorate(
//		func(e Example) Example {
//			return e.WithMoreMagic()
//		},
//		cell.Invoke(func(e Example) {
//			// e now has more magic
//		},
//	)
func Decorate(dtor any, cells ...Cell) Cell {
	return &decorator{
		decorator: dtor,
		cells:     cells,
	}
}

type decorator struct {
	decorator any
	cells     []Cell
}

func (d *decorator) Apply(c container) error {
	scope := c.Scope(fmt.Sprintf("(decorate %s)", internal.PrettyType(d.decorator)))
	if err := scope.Decorate(d.decorator); err != nil {
		return err
	}

	for _, cell := range d.cells {
		if err := cell.Apply(scope); err != nil {
			return err
		}
	}

	return nil
}

func (d *decorator) Info(c container) Info {
	n := NewInfoNode(fmt.Sprintf("🔀 %s: %s", internal.FuncNameAndLocation(d.decorator), internal.PrettyType(d.decorator)))
	for _, cell := range d.cells {
		n.Add(cell.Info(c))
	}
	return n
}
