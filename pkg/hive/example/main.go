// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

// exampleCell is a module providing a configuration
// object (ExampleConfig) and a normal object (*ExampleObject).
//
// A module is a named collection of cells. It establishes
// a new scope for private constructors. Nested modules have access
// to private constructors in the parent's scope, but not the other
// way around.
var exampleCell = cell.Module(
	"example",
	"Example",

	cell.Config(defaultExampleConfig),
	cell.Provide(newExampleObject),
	cell.ProvidePrivate(newPrivateObject),
)

func main() {
	dotGraph := pflag.Bool("dot-graph", false, "Dump graphviz dot graph")

	// Create a hive from a set of cells.
	hive := hive.New(
		exampleCell,

		// Constructors are lazy and only invoked if they are a dependency
		// to an "invoke" function or an indirect dependency of a constructor
		// referenced in an invoke.
		//
		// Think of invoke functions as the driver that decides what things
		// should be constructed and how they should integrate with each other.
		//
		// Modules that provide a service should usually not have any invoke
		// functions that force object construction whether or not it is needed.
		cell.Invoke(func(*ExampleObject) {}),
	)

	// Register the flags and parse them.
	hive.RegisterFlags(pflag.CommandLine)
	pflag.Parse()

	// If dot graph is requested, dump it to stdout.
	// Try piping it to "dot -Tx11" to visualize (or -Tpng on macOS).
	if *dotGraph {
		hive.PrintDotGraph()
		return
	}

	// PrintObjects can be used to visualize all the cells to inspect
	// what objects can be constructed, or in what order start hooks
	// run.
	hive.PrintObjects()

	// Now that flags have been parsed the hive can be started.
	// This first populates all configurations from Viper (and via pflag)
	// and then constructs all objects, followed by executing the start
	// hooks in dependency order. It will then block waiting for signals
	// after which it will run the stop hooks in reverse order.
	if err := hive.Run(); err != nil {
		// Run() can fail if:
		// - There are missing types in the object graph
		// - Executing the lifecycle start or stop hooks fails
		// - Shutdown is called with an error
		fmt.Printf("hive.Run() error: %s", err)
	}
}

// ExampleConfig is a configuration struct that is used with cell.Config.
// The field names are by convention matched up with command-line flag
// names by removing dashes from flag name and doing a case insensitive
// comparison. E.g. DashedFieldName matches dashed-field-name. The correspondence
// can also be manually specified with struct tag: `mapstructure:"flag-name-here"`.
type ExampleConfig struct {
	Foo             string
	Bar             float32
	DashedFieldName int
}

// Flags registers the fields in ExampleConfig as command-line arguments.
// The receiver 'def' is the "defaultExampleConfig" we pass to cell.Config.
//
// This construction allows creating cells with parametrized defaults:
//
//	func NewExample(def ExampleConfig) cell.Cell {
//		return cell.Module(cell.Config(def), ... )
//	}
//
// See pkg/gops/cell.go for example.
func (def ExampleConfig) Flags(flags *pflag.FlagSet) {
	flags.String("foo", def.Foo, "foo flag")
	flags.Float32("bar", def.Bar, "bar flag")
	flags.Int("dashed-field-name", def.DashedFieldName, "dashed")
}

// defaultExampleConfig is the defaults for the configuration.
var defaultExampleConfig = ExampleConfig{
	Foo:             "",
	Bar:             0.25,
	DashedFieldName: 10,
}

type privateObject struct {
}

func newPrivateObject() *privateObject {
	return &privateObject{}
}

type ExampleObject struct {
	cfg ExampleConfig
	log logrus.FieldLogger
}

// onStart is a lifecycle hook that is executed when the hive is started.
// If onStart fails, then hive will rewind by calling stop hooks for
// already started components and then return the error.
//
// The HookContext is provided to allow aborting the start in case of
// a timeout. It should always be used to abort any long running operation
// performed directly from the start hook.
func (o *ExampleObject) onStart(hive.HookContext) error {
	o.log.Infof("onStart: Config: %#v", o.cfg)
	return nil
}

// onStop is a lifecycle hook that is executed when the hive is stopped,
// either by a signal (SIGINT (ctrl-c), SIGTERM) or a call to Shutdowner.Shutdown().
// All stop hooks are executed regardless if one fails.
func (o *ExampleObject) onStop(hive.HookContext) error {
	o.log.Info("onStop")
	return nil
}

// newExampleObject constructs ExampleObject.
//
// It depends on hive.Lifecycle to insert the start and stop hooks that are executed
// when the hive is run. These are inserted in the order which the constructors are
// called, and since they are called in dependency order, the hooks will also be in
// dependency order.
//
// It also depends on ExampleConfig, which is provided via "cell.Config". Hive will
// call ExampleConfig.Flags() in hive.New() to construct the flag set for all the cells.
// This flag set can be added to the applications flag set via RegisterFlags().
//
// Finally it depends on logrus.FieldLogger which is globally available to all cells.
// If the cell is wrapped in a cell.Module the logger will be scoped to that module
// with the subsys field set to module name.
func newExampleObject(lc hive.Lifecycle, cfg ExampleConfig, p *privateObject, log logrus.FieldLogger) *ExampleObject {
	obj := &ExampleObject{cfg: cfg, log: log}
	lc.Append(hive.Hook{OnStart: obj.onStart, OnStop: obj.onStop})
	log.Info("ExampleObject constructed")
	return obj
}
