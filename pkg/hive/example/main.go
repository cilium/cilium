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
	"github.com/cilium/cilium/pkg/hive/cell"
)

type ExampleConfig struct {
	Foo             string
	Bar             float32
	DashedFieldName int
}

var defaultExampleConfig = ExampleConfig{
	Foo:             "",
	Bar:             0.25,
	DashedFieldName: 10,
}

// Flags registers the fields in ExampleConfig as command-line arguments.
// The receiver is the "defaultExampleConfig" we pass to cell.Config.
func (def ExampleConfig) Flags(flags *pflag.FlagSet) {
	flags.String("foo", def.Foo, "foo flag")
	flags.Float32("bar", def.Bar, "bar flag")
	flags.Int("dashed-field-name", def.DashedFieldName, "dashed")
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

var exampleCell = cell.Module(
	"example",
	cell.Config(defaultExampleConfig),
	cell.Provide(newExampleObject),
)

func main() {
	// Construct the hive. This registers all command-line flags
	// from the cells to the given FlagSet.
	hive := hive.New(
		viper.New(), pflag.CommandLine,

		exampleCell,

		// Mark *ExampleObject as required to force its construction.
		// By default the provided constructors are not called if
		// they're not marked required, or used in "fx.Invoke" directly
		// or indirectly.
		cell.Invoke(func(*ExampleObject) {}),
	)

	// After hive.New the command-line flags have been registered.
	// Before we run the hive, we need to parse the flags.
	pflag.Parse()

	// Now that flags have been parsed the hive can be started.
	// This first populates all configurations from Viper (and via pflag)
	// and then constructs all objects, followed by executing the start
	// hooks in dependency order. It will then block waiting for signals
	// after which it will run the stop hooks in reverse order.
	hive.Run()
}
