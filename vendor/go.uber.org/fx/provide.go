// Copyright (c) 2022 Uber Technologies, Inc.
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

	"go.uber.org/dig"
	"go.uber.org/fx/internal/fxreflect"
)

// Provide registers any number of constructor functions, teaching the
// application how to instantiate various types. The supplied constructor
// function(s) may depend on other types available in the application, must
// return one or more objects, and may return an error. For example:
//
//	// Constructs type *C, depends on *A and *B.
//	func(*A, *B) *C
//
//	// Constructs type *C, depends on *A and *B, and indicates failure by
//	// returning an error.
//	func(*A, *B) (*C, error)
//
//	// Constructs types *B and *C, depends on *A, and can fail.
//	func(*A) (*B, *C, error)
//
// The order in which constructors are provided doesn't matter, and passing
// multiple Provide options appends to the application's collection of
// constructors. Constructors are called only if one or more of their returned
// types are needed, and their results are cached for reuse (so instances of a
// type are effectively singletons within an application). Taken together,
// these properties make it perfectly reasonable to Provide a large number of
// constructors even if only a fraction of them are used.
//
// See the documentation of the In and Out types for advanced features,
// including optional parameters and named instances.
//
// Constructor functions should perform as little external interaction as
// possible, and should avoid spawning goroutines. Things like server listen
// loops, background timer loops, and background processing goroutines should
// instead be managed using Lifecycle callbacks.
func Provide(constructors ...interface{}) Option {
	return provideOption{
		Targets: constructors,
		Stack:   fxreflect.CallerStack(1, 0),
	}
}

type provideOption struct {
	Targets []interface{}
	Stack   fxreflect.Stack
}

func (o provideOption) apply(mod *module) {
	for _, target := range o.Targets {
		mod.provides = append(mod.provides, provide{
			Target: target,
			Stack:  o.Stack,
		})
	}
}

func (o provideOption) String() string {
	items := make([]string, len(o.Targets))
	for i, c := range o.Targets {
		items[i] = fxreflect.FuncName(c)
	}
	return fmt.Sprintf("fx.Provide(%s)", strings.Join(items, ", "))
}

func runProvide(c container, p provide, opts ...dig.ProvideOption) error {
	constructor := p.Target
	if _, ok := constructor.(Option); ok {
		return fmt.Errorf("fx.Option should be passed to fx.New directly, "+
			"not to fx.Provide: fx.Provide received %v from:\n%+v",
			constructor, p.Stack)
	}

	switch constructor := constructor.(type) {
	case annotationError:
		// fx.Annotate failed. Turn it into an Fx error.
		return fmt.Errorf(
			"encountered error while applying annotation using fx.Annotate to %s: %+v",
			fxreflect.FuncName(constructor.target), constructor.err)

	case annotated:
		ctor, err := constructor.Build()
		if err != nil {
			return fmt.Errorf("fx.Provide(%v) from:\n%+vFailed: %v", constructor, p.Stack, err)
		}

		opts = append(opts, dig.LocationForPC(constructor.FuncPtr))
		if err := c.Provide(ctor, opts...); err != nil {
			return fmt.Errorf("fx.Provide(%v) from:\n%+vFailed: %v", constructor, p.Stack, err)
		}

	case Annotated:
		ann := constructor
		switch {
		case len(ann.Group) > 0 && len(ann.Name) > 0:
			return fmt.Errorf(
				"fx.Annotated may specify only one of Name or Group: received %v from:\n%+v",
				ann, p.Stack)
		case len(ann.Name) > 0:
			opts = append(opts, dig.Name(ann.Name))
		case len(ann.Group) > 0:
			opts = append(opts, dig.Group(ann.Group))
		}

		if err := c.Provide(ann.Target, opts...); err != nil {
			return fmt.Errorf("fx.Provide(%v) from:\n%+vFailed: %v", ann, p.Stack, err)
		}

	default:
		if reflect.TypeOf(constructor).Kind() == reflect.Func {
			ft := reflect.ValueOf(constructor).Type()

			for i := 0; i < ft.NumOut(); i++ {
				t := ft.Out(i)

				if t == reflect.TypeOf(Annotated{}) {
					return fmt.Errorf(
						"fx.Annotated should be passed to fx.Provide directly, "+
							"it should not be returned by the constructor: "+
							"fx.Provide received %v from:\n%+v",
						fxreflect.FuncName(constructor), p.Stack)
				}
			}
		}

		if err := c.Provide(constructor, opts...); err != nil {
			return fmt.Errorf("fx.Provide(%v) from:\n%+vFailed: %v", fxreflect.FuncName(constructor), p.Stack, err)
		}
	}
	return nil
}
