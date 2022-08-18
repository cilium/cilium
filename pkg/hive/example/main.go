// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"fmt"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/fx"

	"github.com/cilium/cilium/pkg/hive"
)

type ExampleConfig struct {
	Foo             string
	Bar             float32
	DashedFieldName int
}

func (ExampleConfig) CellFlags(flags *pflag.FlagSet) {
	flags.String("foo", "", "foo flag")
	flags.Float32("bar", 0.25, "bar flag")
	flags.Int("dashed-field-name", 10, "dashed")
}

type ExampleObject struct {
	cfg ExampleConfig
}

func (o *ExampleObject) onStart(context.Context) error {
	fmt.Printf(">>> ExampleObject.OnStart: Config: %#v\n", o.cfg)
	return nil
}

func (o *ExampleObject) onStop(context.Context) error {
	fmt.Printf(">>> ExampleObject.OnStop\n")
	return nil
}

func newExampleObject(lc fx.Lifecycle, cfg ExampleConfig) *ExampleObject {
	obj := &ExampleObject{cfg}
	lc.Append(fx.Hook{OnStart: obj.onStart, OnStop: obj.onStop})
	return obj
}

var exampleCell = hive.NewCellWithConfig[ExampleConfig](
	"example",
	fx.Provide(newExampleObject),
)

func main() {
	// Construct the hive. This registers all command-line flags
	// from the cells to the given FlagSet.
	hive := hive.New(
		viper.New(), pflag.CommandLine,

		exampleCell,

		hive.Require[*ExampleObject](),
	)

	pflag.Parse()

	// Now that flags have been parsed the hive can be started.
	hive.Run()
}
