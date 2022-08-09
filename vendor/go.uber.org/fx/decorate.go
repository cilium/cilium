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
	"strings"

	"go.uber.org/dig"
	"go.uber.org/fx/internal/fxreflect"
)

// Decorate specifies one or more decorator functions to an Fx application.
//
// # Decorator functions
//
// Decorator functions let users augment objects in the graph.
// They can take in zero or more dependencies that must be provided to the
// application with fx.Provide, and produce one or more values that can be used
// by other fx.Provide and fx.Invoke calls.
//
//	fx.Decorate(func(log *zap.Logger) *zap.Logger {
//	  return log.Named("myapp")
//	})
//	fx.Invoke(func(log *zap.Logger) {
//	  log.Info("hello")
//	  // Output:
//	  // {"level": "info","logger":"myapp","msg":"hello"}
//	})
//
// The following decorator accepts multiple dependencies from the graph,
// augments and returns one of them.
//
//	fx.Decorate(func(log *zap.Logger, cfg *Config) *zap.Logger {
//	  return log.Named(cfg.Name)
//	})
//
// Similar to fx.Provide, functions passed to fx.Decorate may optionally return
// an error as their last result.
// If a decorator returns a non-nil error, it will halt application startup.
//
//	fx.Decorate(func(conn *sql.DB, cfg *Config) (*sql.DB, error) {
//	  if err := conn.Ping(); err != nil {
//	    return sql.Open("driver-name", cfg.FallbackDB)
//	  }
//	  return conn, nil
//	})
//
// Decorators support both, fx.In and fx.Out structs, similar to fx.Provide and
// fx.Invoke.
//
//	type Params struct {
//	  fx.In
//
//	  Client usersvc.Client `name:"readOnly"`
//	}
//
//	type Result struct {
//	  fx.Out
//
//	  Client usersvc.Client `name:"readOnly"`
//	}
//
//	fx.Decorate(func(p Params) Result {
//	  ...
//	})
//
// Decorators can be annotated with the fx.Annotate function, but not with the
// fx.Annotated type. Refer to documentation on fx.Annotate() to learn how to
// use it for annotating functions.
//
//	fx.Decorate(
//	  fx.Annotate(
//	    func(client usersvc.Client) usersvc.Client {
//	      // ...
//	    },
//	    fx.ParamTags(`name:"readOnly"`),
//	    fx.ResultTags(`name:"readOnly"`),
//	  ),
//	)
//
// Decorators support augmenting, filtering, or replacing value groups.
// To decorate a value group, expect the entire value group slice and produce
// the new slice.
//
//	type HandlerParam struct {
//	  fx.In
//
//	  Log      *zap.Logger
//	  Handlers []Handler `group:"server"
//	}
//
//	type HandlerResult struct {
//	  fx.Out
//
//	  Handlers []Handler `group:"server"
//	}
//
//	fx.Decorate(func(p HandlerParam) HandlerResult {
//	  var r HandlerResult
//	  for _, handler := range p.Handlers {
//	    r.Handlers = append(r.Handlers, wrapWithLogger(p.Log, handler))
//	  }
//	  return r
//	}),
//
// # Decorator scope
//
// Modifications made to the Fx graph with fx.Decorate are scoped to the
// deepest fx.Module inside which the decorator was specified.
//
//	fx.Module("mymodule",
//	  fx.Decorate(func(log *zap.Logger) *zap.Logger {
//	    return log.Named("myapp")
//	  }),
//	  fx.Invoke(func(log *zap.Logger) {
//	    log.Info("decorated logger")
//	    // Output:
//	    // {"level": "info","logger":"myapp","msg":"decorated logger"}
//	  }),
//	),
//	fx.Invoke(func(log *zap.Logger) {
//	  log.Info("plain logger")
//	  // Output:
//	  // {"level": "info","msg":"plain logger"}
//	}),
//
// Decorations specified in the top-level fx.New call apply across the
// application and chain with module-specific decorators.
//
//	fx.New(
//	  // ...
//	  fx.Decorate(func(log *zap.Logger) *zap.Logger {
//	    return log.With(zap.Field("service", "myservice"))
//	  }),
//	  // ...
//	  fx.Invoke(func(log *zap.Logger) {
//	    log.Info("outer decorator")
//	    // Output:
//	    // {"level": "info","service":"myservice","msg":"outer decorator"}
//	  }),
//	  // ...
//	  fx.Module("mymodule",
//	    fx.Decorate(func(log *zap.Logger) *zap.Logger {
//	      return log.Named("myapp")
//	    }),
//	    fx.Invoke(func(log *zap.Logger) {
//	      log.Info("inner decorator")
//	      // Output:
//	      // {"level": "info","logger":"myapp","service":"myservice","msg":"inner decorator"}
//	    }),
//	  ),
//	)
func Decorate(decorators ...interface{}) Option {
	return decorateOption{
		Targets: decorators,
		Stack:   fxreflect.CallerStack(1, 0),
	}
}

type decorateOption struct {
	Targets []interface{}
	Stack   fxreflect.Stack
}

func (o decorateOption) apply(mod *module) {
	for _, target := range o.Targets {
		mod.decorators = append(mod.decorators, decorator{
			Target: target,
			Stack:  o.Stack,
		})
	}
}

func (o decorateOption) String() string {
	items := make([]string, len(o.Targets))
	for i, f := range o.Targets {
		items[i] = fxreflect.FuncName(f)
	}
	return fmt.Sprintf("fx.Decorate(%s)", strings.Join(items, ", "))
}

// decorator is a single decorator used in Fx.
type decorator struct {
	// Decorator provided to Fx.
	Target interface{}

	// Stack trace of where this provide was made.
	Stack fxreflect.Stack

	// Whether this decorator was specified via fx.Replace
	IsReplace bool
}

func runDecorator(c container, d decorator, opts ...dig.DecorateOption) (err error) {
	decorator := d.Target
	defer func() {
		if err != nil {
			err = fmt.Errorf("fx.Decorate(%v) from:\n%+vFailed: %v", decorator, d.Stack, err)
		}
	}()

	switch decorator := decorator.(type) {
	case annotated:
		if dcor, derr := decorator.Build(); derr == nil {
			err = c.Decorate(dcor, opts...)
		}
	default:
		err = c.Decorate(decorator, opts...)
	}
	return
}
