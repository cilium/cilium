// Copyright (c) 2020 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package fx

import (
	"fmt"
	"reflect"
	"strings"

	"go.uber.org/fx/internal/fxreflect"
)

// Supply provides instantiated values for dependency injection as if
// they had been provided using a constructor that simply returns them.
// The most specific type of each value (as determined by reflection) is used.
//
// For example, given:
//
//  type (
//  	TypeA struct{}
//  	TypeB struct{}
//  	TypeC struct{}
//  )
//
//  var a, b, c = &TypeA{}, TypeB{}, &TypeC{}
//
// The following two forms are equivalent:
//
//  fx.Supply(a, b, fx.Annotated{Target: c})
//
//  fx.Provide(
//  	func() *TypeA { return a },
//  	func() TypeB { return b },
//  	fx.Annotated{Target: func() *TypeC { return c }},
//  )
//
// Supply panics if a value (or annotation target) is an untyped nil or an error.
func Supply(values ...interface{}) Option {
	constructors := make([]interface{}, len(values)) // one function per value
	types := make([]reflect.Type, len(values))
	for i, value := range values {
		switch value := value.(type) {
		case Annotated:
			var typ reflect.Type
			value.Target, typ = newSupplyConstructor(value.Target)
			constructors[i] = value
			types[i] = typ
		default:
			constructors[i], types[i] = newSupplyConstructor(value)
		}
	}

	return supplyOption{
		Targets: constructors,
		Types:   types,
		Stack:   fxreflect.CallerStack(1, 0),
	}
}

type supplyOption struct {
	Targets []interface{}
	Types   []reflect.Type // type of value produced by constructor[i]
	Stack   fxreflect.Stack
}

func (o supplyOption) apply(app *App) {
	for i, target := range o.Targets {
		app.provides = append(app.provides, provide{
			Target:     target,
			Stack:      o.Stack,
			IsSupply:   true,
			SupplyType: o.Types[i],
		})
	}
}

func (o supplyOption) String() string {
	items := make([]string, 0, len(o.Targets))
	for _, typ := range o.Types {
		items = append(items, typ.String())
	}
	return fmt.Sprintf("fx.Supply(%s)", strings.Join(items, ", "))
}

// Returns a function that takes no parameters, and returns the given value.
func newSupplyConstructor(value interface{}) (interface{}, reflect.Type) {
	switch value.(type) {
	case nil:
		panic("untyped nil passed to fx.Supply")
	case error:
		panic("error value passed to fx.Supply")
	}

	typ := reflect.TypeOf(value)
	returnTypes := []reflect.Type{typ}
	returnValues := []reflect.Value{reflect.ValueOf(value)}

	ft := reflect.FuncOf([]reflect.Type{}, returnTypes, false)
	fv := reflect.MakeFunc(ft, func([]reflect.Value) []reflect.Value {
		return returnValues
	})

	return fv.Interface(), typ
}
