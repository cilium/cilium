// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"github.com/spf13/pflag"
	"go.uber.org/fx"
)

type decorator struct {
	decorator fx.Option
	cells     []Cell
}

func (d *decorator) RegisterFlags(flags *pflag.FlagSet) {
	for _, cell := range d.cells {
		cell.RegisterFlags(flags)
	}
}

func (d *decorator) ToOption(settings map[string]any) (fx.Option, error) {
	opts := []fx.Option{d.decorator}
	for _, cell := range d.cells {
		opt, err := cell.ToOption(settings)
		if err != nil {
			return nil, err
		}
		opts = append(opts, opt)
	}
	return fx.Module("", opts...), nil
}

// Decorate takes a decorator function and a set of cells and returns
// a decorator cell.
//
// A decorator function is a function that takes as arguments objects
// in the hive and returns one or more augmented objects. The cells wrapped
// with a decorator will be provided the returned augmented objects.
//
// Example:
//
//	Decorate(
//		func(e Example) Example {
//			return e.WithMoreMagic()
//		},
//		wizardCell,
//	)
func Decorate(dtor any, cells ...Cell) Cell {
	return &decorator{
		decorator: fx.Decorate(dtor),
		cells:     cells,
	}
}
