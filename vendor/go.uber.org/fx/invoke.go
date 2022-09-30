// Copyright (c) 2019-2021 Uber Technologies, Inc.
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
	"strings"

	"go.uber.org/fx/internal/fxreflect"
)

// Invoke registers functions that are executed eagerly on application start.
// Arguments for these invocations are built using the constructors registered
// by Provide. Passing multiple Invoke options appends the new invocations to
// the application's existing list.
//
// Unlike constructors, invocations are always executed, and they're always
// run in order. Invocations may have any number of returned values.
// If the final returned object is an error, it indicates whether the operation
// was successful.
// All other returned values are discarded.
//
// Invokes registered in [Module]s are run before the ones registered at the
// scope of the parent. Invokes within the same Module is run in the order
// they were provided. For example,
//
//	fx.New(
//		fx.Invoke(func3),
//		fx.Module("someModule",
//			fx.Invoke(func1),
//			fx.Invoke(func2),
//		),
//		fx.Invoke(func4),
//	)
//
// invokes func1, func2, func3, func4 in that order.
//
// Typically, invoked functions take a handful of high-level objects (whose
// constructors depend on lower-level objects) and introduce them to each
// other. This kick-starts the application by forcing it to instantiate a
// variety of types.
//
// To see an invocation in use, read through the package-level example. For
// advanced features, including optional parameters and named instances, see
// the documentation of the In and Out types.
func Invoke(funcs ...interface{}) Option {
	return invokeOption{
		Targets: funcs,
		Stack:   fxreflect.CallerStack(1, 0),
	}
}

type invokeOption struct {
	Targets []interface{}
	Stack   fxreflect.Stack
}

func (o invokeOption) apply(mod *module) {
	for _, target := range o.Targets {
		mod.invokes = append(mod.invokes, invoke{
			Target: target,
			Stack:  o.Stack,
		})
	}
}

func (o invokeOption) String() string {
	items := make([]string, len(o.Targets))
	for i, f := range o.Targets {
		items[i] = fxreflect.FuncName(f)
	}
	return fmt.Sprintf("fx.Invoke(%s)", strings.Join(items, ", "))
}
func runInvoke(c container, i invoke) error {
	fn := i.Target
	switch fn := fn.(type) {
	case Option:
		return fmt.Errorf("fx.Option should be passed to fx.New directly, "+
			"not to fx.Invoke: fx.Invoke received %v from:\n%+v",
			fn, i.Stack)

	case annotated:
		af, err := fn.Build()
		if err != nil {
			return err
		}

		return c.Invoke(af)
	default:
		return c.Invoke(fn)
	}
}
