// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"context"
	"fmt"
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
	flags         []string // Flags registered for the cell. Populated after call to registerFlags().
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

// OnStart registers a function of form "func(a A, b B, ...) error" to run on start up.
// The function can take any number of arguments.
//
// For example:
//
//	func myStartFunc(a A, b B) error
//	OnStart(myStartFunc)
//
// This will append a start hook to run myStartFunc after A and B have been constructed
// and their start hooks have been executed. This is equivalent to the long form:
//
//	NewCell("", fx.Invoke(func(lc fx.Lifecycle, a A, b B) {
//		lc.Append(fx.Hook{OnStart: func(context.Context) error {
//			return myStartFunc(a, b)
//	  	})
//	}))
func OnStart(fn any) *Cell {
	typ := reflect.TypeOf(fn)
	if typ.Kind() != reflect.Func {
		panic(fmt.Sprintf("OnStart called with unsupported type %s. Argument must be a function", typ))
	}

	in := []reflect.Type{reflect.TypeOf(new(fx.Lifecycle)).Elem()}
	for i := 0; i < typ.NumIn(); i++ {
		in = append(in, typ.In(i))
	}
	errType := reflect.TypeOf(new(error)).Elem()
	if typ.NumOut() != 1 || !typ.Out(0).Implements(errType) {
		panic(fmt.Sprintf("OnStart called with unsupported type %s. Start function needs to return an error", typ))
	}

	// Construct a wrapper function that takes the same arguments plus lifecycle.
	// The wrapper will append a start hook and will then invoke the original function
	// from the start hook.
	// We ignore any outputs from the function.
	funTyp := reflect.FuncOf(in, []reflect.Type{}, false)
	funVal := reflect.MakeFunc(funTyp, func(args []reflect.Value) []reflect.Value {
		lc := args[0].Interface().(fx.Lifecycle)
		lc.Append(fx.Hook{
			OnStart: func(context.Context) error {
				result := reflect.ValueOf(fn).Call(args[1:])
				if result[0].IsNil() {
					return nil
				} else {
					return result[0].Interface().(error)
				}
			},
		})
		return []reflect.Value{}
	})
	return NewCell("", fx.Invoke(funVal.Interface()))
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
