// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"github.com/spf13/pflag"
	"go.uber.org/fx"
)

type invoker struct {
	funcs []any
}

func (*invoker) RegisterFlags(*pflag.FlagSet) {}

func (c *invoker) ToOption(settings map[string]any) (fx.Option, error) {
	return fx.Invoke(c.funcs...), nil
}

// Invoke constructs a cell for invoke functions. The invoke functions are executed
// when the hive is started to instantiate all objects via the constructors.
func Invoke(funcs ...any) Cell {
	return &invoker{funcs}
}
