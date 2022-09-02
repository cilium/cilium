// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"reflect"

	"github.com/spf13/pflag"
	"go.uber.org/fx"
)

// CellConfigFlags is implemented by configuration structs for registering
// their command-line flags.
type CellConfig interface {
	// Flags registers the configuration options as command-line flags.
	//
	// By convention a flag name matches the field name
	// if they're the same under case-insensitive comparison when dashes are
	// removed. E.g. "my-config-flag" matches field "MyConfigFlag". The
	// correspondence to the flag can be also specified with the mapstructure
	// tag: MyConfigFlag `mapstructure:"my-config-flag"`.
	//
	// Exported fields that are not found from the viper settings will cause
	// hive.Run() to fail. Unexported fields are ignored.
	//
	// See https://pkg.go.dev/github.com/mitchellh/mapstructure for more info.
	Flags(*pflag.FlagSet)

	// Validate is called after the struct has been populated to
	// validate that fields have valid values. Validate can also
	// modify fields (if implemented as pointer receiver), or fill in
	// unexported fields to provide pre-parsed values for getters.
	Validate() error
}

type Cells interface {
	Cells() []*Cell
}

type CellGroup []*Cell

func (g CellGroup) Cells() []*Cell {
	return g
}

// Cell is a modular component of the hive, consisting of configuration and
// a set of constructors and objects (as fx.Options).
type Cell struct {
	flags     *pflag.FlagSet
	config    CellConfig
	hasConfig bool
	name      string
	opts      []fx.Option
}

func (c *Cell) Cells() []*Cell {
	return []*Cell{c}
}

// NewCell constructs a new cell with the given name and options.
func NewCell(name string, opts ...fx.Option) *Cell {
	return &Cell{
		name: name,
		opts: opts,
	}
}

// NewCellWithConfig constructs a new cell with the name, configuration
// and options
//
// The structure is populated and provided via dependency
// injection by Hive.Run(). The underlying mechanism for populating the struct
// is via mapstructure library, with settings from viper, e.g. they can be
// set either via command-line flags or via viper (config files etc.).
func NewCellWithConfig(name string, config CellConfig, opts ...fx.Option) *Cell {
	c := &Cell{
		name:      name,
		opts:      opts,
		config:    config,
		hasConfig: true,
		flags: pflag.NewFlagSet("", pflag.ContinueOnError),
	}
	config.Flags(c.flags)
	return c
}

// NewConfigCell constructs an anonymous cell with only a configuration.
func NewConfigCell(config CellConfig) *Cell {
	return NewCellWithConfig("", config)
}

// Invoke constructs an unnamed cell for an invoke function.
func Invoke(fn any) *Cell {
	return NewCell("", fx.Invoke(fn))
}

// Require constructs a cell that ensures the object T is
// always instantiated even if nothing refers to it.
func Require[T any]() *Cell {
	var v T
	typ := reflect.TypeOf(v)
	// Construct the function of type 'func(T)'
	funTyp := reflect.FuncOf([]reflect.Type{typ}, []reflect.Type{}, false)
	funVal := reflect.MakeFunc(funTyp, func([]reflect.Value) []reflect.Value {
		return []reflect.Value{}
	})
	return Invoke(funVal.Interface())
}
