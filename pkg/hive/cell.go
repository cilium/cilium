// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"reflect"

	"github.com/spf13/pflag"
	"go.uber.org/fx"
)

// CellConfig is implemented by configuration structs to provide configuration
// for a cell.
type CellConfig interface {
	// CellFlags registers the configuration options as command-line flags.
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
	CellFlags(*pflag.FlagSet)
}

// Cell is a modular component of the hive, consisting of configuration and
// a set of constructors and objects (as fx.Options).
type Cell struct {
	newConfig     func() any
	registerFlags func(*pflag.FlagSet)
	name          string
	opts          []fx.Option
}

// NewCell constructs a new cell with the given name and options.
func NewCell(name string, opts ...fx.Option) *Cell {
	return &Cell{
		name:          name,
		opts:          opts,
		registerFlags: func(*pflag.FlagSet) {},
		newConfig:     nil,
	}
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

// NewCellWithConfig constructs a new cell with the name, configuration
// and options
//
// The configuration struct `T` needs to implement CellFlags method that
// registers the flags. The structure is populated and provided via dependency
// injection by Hive.Run(). The underlying mechanism for populating the struct
// is viper's Unmarshal().
func NewCellWithConfig[T CellConfig](name string, opts ...fx.Option) *Cell {
	var emptyConfig T
	return &Cell{
		name:          name,
		opts:          opts,
		registerFlags: emptyConfig.CellFlags,
		newConfig:     func() any { return emptyConfig },
	}
}
