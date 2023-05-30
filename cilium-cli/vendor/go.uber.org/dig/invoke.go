// Copyright (c) 2021 Uber Technologies, Inc.
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

package dig

import (
	"fmt"
	"go.uber.org/dig/internal/digreflect"
	"go.uber.org/dig/internal/graph"
	"reflect"
)

// An InvokeOption modifies the default behavior of Invoke.
type InvokeOption interface {
	applyInvokeOption(*invokeOptions)
}

type invokeOptions struct {
	Info *InvokeInfo
}

// InvokeInfo provides information about an Invoke.
type InvokeInfo struct {
	Inputs []*Input
}

// FillInvokeInfo is an InvokeOption that writes information on the types
// accepted by the Invoke function into the specified InvokeInfo.
// For example:
//
//			var info dig.InvokeInfo
//			err := c.Invoke(func(string, int){}, dig.FillInvokeInfo(&info))
//
//	  info.Inputs[0].String() will be string.
//	  info.Inputs[1].String() will be int.
func FillInvokeInfo(info *InvokeInfo) InvokeOption {
	return fillInvokeInfoOption{info: info}
}

type fillInvokeInfoOption struct {
	info *InvokeInfo
}

func (o fillInvokeInfoOption) String() string {
	return fmt.Sprintf("FillInvokeInfo(%p)", o.info)
}

func (o fillInvokeInfoOption) applyInvokeOption(opts *invokeOptions) {
	opts.Info = o.info
}

// Invoke runs the given function after instantiating its dependencies.
//
// Any arguments that the function has are treated as its dependencies. The
// dependencies are instantiated in an unspecified order along with any
// dependencies that they might have.
//
// The function may return an error to indicate failure. The error will be
// returned to the caller as-is.
//
// If the [RecoverFromPanics] option was given to the container and a panic
// occurs when invoking, a [PanicError] with the panic contained will be
// returned. See [PanicError] for more info.
func (c *Container) Invoke(function interface{}, opts ...InvokeOption) error {
	return c.scope.Invoke(function, opts...)
}

// Invoke runs the given function after instantiating its dependencies.
//
// Any arguments that the function has are treated as its dependencies. The
// dependencies are instantiated in an unspecified order along with any
// dependencies that they might have.
//
// The function may return an error to indicate failure. The error will be
// returned to the caller as-is.
func (s *Scope) Invoke(function interface{}, opts ...InvokeOption) (err error) {
	ftype := reflect.TypeOf(function)
	if ftype == nil {
		return newErrInvalidInput("can't invoke an untyped nil", nil)
	}
	if ftype.Kind() != reflect.Func {
		return newErrInvalidInput(
			fmt.Sprintf("can't invoke non-function %v (type %v)", function, ftype), nil)
	}

	pl, err := newParamList(ftype, s)
	if err != nil {
		return err
	}

	if err := shallowCheckDependencies(s, pl); err != nil {
		return errMissingDependencies{
			Func:   digreflect.InspectFunc(function),
			Reason: err,
		}
	}

	if !s.isVerifiedAcyclic {
		if ok, cycle := graph.IsAcyclic(s.gh); !ok {
			return newErrInvalidInput("cycle detected in dependency graph", s.cycleDetectedError(cycle))
		}
		s.isVerifiedAcyclic = true
	}

	args, err := pl.BuildList(s)
	if err != nil {
		return errArgumentsFailed{
			Func:   digreflect.InspectFunc(function),
			Reason: err,
		}
	}
	if s.recoverFromPanics {
		defer func() {
			if p := recover(); p != nil {
				err = PanicError{
					fn:    digreflect.InspectFunc(function),
					Panic: p,
				}
			}
		}()
	}

	var options invokeOptions
	for _, o := range opts {
		o.applyInvokeOption(&options)
	}

	// Record info for the invoke if requested
	if info := options.Info; info != nil {
		params := pl.DotParam()
		info.Inputs = make([]*Input, len(params))
		for i, p := range params {
			info.Inputs[i] = &Input{
				t:        p.Type,
				optional: p.Optional,
				name:     p.Name,
				group:    p.Group,
			}
		}

	}

	returned := s.invokerFn(reflect.ValueOf(function), args)
	if len(returned) == 0 {
		return nil
	}
	if last := returned[len(returned)-1]; isError(last.Type()) {
		if err, _ := last.Interface().(error); err != nil {
			return err
		}
	}

	return nil
}

// Checks that all direct dependencies of the provided parameters are present in
// the container. Returns an error if not.
func shallowCheckDependencies(c containerStore, pl paramList) error {
	var err errMissingTypes

	missingDeps := findMissingDependencies(c, pl.Params...)
	for _, dep := range missingDeps {
		err = append(err, newErrMissingTypes(c, key{name: dep.Name, t: dep.Type})...)
	}

	if len(err) > 0 {
		return err
	}
	return nil
}

func findMissingDependencies(c containerStore, params ...param) []paramSingle {
	var missingDeps []paramSingle

	for _, param := range params {
		switch p := param.(type) {
		case paramSingle:
			allProviders := c.getAllValueProviders(p.Name, p.Type)
			_, hasDecoratedValue := c.getDecoratedValue(p.Name, p.Type)
			// This means that there is no provider that provides this value,
			// and it is NOT being decorated and is NOT optional.
			// In the case that there is no providers but there is a decorated value
			// of this type, it can be provided safely so we can safely skip this.
			if len(allProviders) == 0 && !hasDecoratedValue && !p.Optional {
				missingDeps = append(missingDeps, p)
			}
		case paramObject:
			for _, f := range p.Fields {
				missingDeps = append(missingDeps, findMissingDependencies(c, f.Param)...)
			}
		}
	}
	return missingDeps
}
