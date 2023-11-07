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
	"reflect"

	"go.uber.org/dig/internal/digerror"
	"go.uber.org/dig/internal/digreflect"
	"go.uber.org/dig/internal/dot"
)

// constructorNode is a node in the dependency graph that represents
// a constructor provided by the user.
//
// constructorNodes can produce zero or more values that they store into the container.
// For the Provide path, we verify that constructorNodes produce at least one value,
// otherwise the function will never be called.
type constructorNode struct {
	ctor  interface{}
	ctype reflect.Type

	// Location where this function was defined.
	location *digreflect.Func

	// id uniquely identifies the constructor that produces a node.
	id dot.CtorID

	// Whether the constructor owned by this node was already called.
	called bool

	// Type information about constructor parameters.
	paramList paramList

	// Type information about constructor results.
	resultList resultList

	// Order of this node in each Scopes' graphHolders.
	orders map[*Scope]int

	// Scope this node is part of.
	s *Scope

	// Scope this node was originally provided to.
	// This is different from s if and only if the constructor was Provided with ExportOption.
	origS *Scope

	// Callback for this provided function, if there is one.
	callback Callback
}

type constructorOptions struct {
	// If specified, all values produced by this constructor have the provided name
	// belong to the specified value group or implement any of the interfaces.
	ResultName  string
	ResultGroup string
	ResultAs    []interface{}
	Location    *digreflect.Func
	Callback    Callback
}

func newConstructorNode(ctor interface{}, s *Scope, origS *Scope, opts constructorOptions) (*constructorNode, error) {
	cval := reflect.ValueOf(ctor)
	ctype := cval.Type()
	cptr := cval.Pointer()

	params, err := newParamList(ctype, s)
	if err != nil {
		return nil, err
	}

	results, err := newResultList(
		ctype,
		resultOptions{
			Name:  opts.ResultName,
			Group: opts.ResultGroup,
			As:    opts.ResultAs,
		},
	)
	if err != nil {
		return nil, err
	}

	location := opts.Location
	if location == nil {
		location = digreflect.InspectFunc(ctor)
	}

	n := &constructorNode{
		ctor:       ctor,
		ctype:      ctype,
		location:   location,
		id:         dot.CtorID(cptr),
		paramList:  params,
		resultList: results,
		orders:     make(map[*Scope]int),
		s:          s,
		origS:      origS,
		callback:   opts.Callback,
	}
	s.newGraphNode(n, n.orders)
	return n, nil
}

func (n *constructorNode) Location() *digreflect.Func { return n.location }
func (n *constructorNode) ParamList() paramList       { return n.paramList }
func (n *constructorNode) ResultList() resultList     { return n.resultList }
func (n *constructorNode) ID() dot.CtorID             { return n.id }
func (n *constructorNode) CType() reflect.Type        { return n.ctype }
func (n *constructorNode) Order(s *Scope) int         { return n.orders[s] }
func (n *constructorNode) OrigScope() *Scope          { return n.origS }

// CopyOrder copies the order for the given parent scope to the given child scope.
func (n *constructorNode) CopyOrder(parent, child *Scope) {
	n.orders[child] = n.orders[parent]
}

func (n *constructorNode) String() string {
	return fmt.Sprintf("deps: %v, ctor: %v", n.paramList, n.ctype)
}

// Call calls this constructor if it hasn't already been called and
// injects any values produced by it into the provided container.
func (n *constructorNode) Call(c containerStore) (err error) {
	if n.called {
		return nil
	}

	if err := shallowCheckDependencies(c, n.paramList); err != nil {
		return errMissingDependencies{
			Func:   n.location,
			Reason: err,
		}
	}

	args, err := n.paramList.BuildList(c)
	if err != nil {
		return errArgumentsFailed{
			Func:   n.location,
			Reason: err,
		}
	}

	if n.callback != nil {
		// Wrap in separate func to include PanicErrors
		defer func() {
			n.callback(CallbackInfo{
				Name:  fmt.Sprintf("%v.%v", n.location.Package, n.location.Name),
				Error: err,
			})
		}()
	}

	if n.s.recoverFromPanics {
		defer func() {
			if p := recover(); p != nil {
				err = PanicError{
					fn:    n.location,
					Panic: p,
				}
			}
		}()
	}

	receiver := newStagingContainerWriter()
	results := c.invoker()(reflect.ValueOf(n.ctor), args)
	if err = n.resultList.ExtractList(receiver, false /* decorating */, results); err != nil {
		return errConstructorFailed{Func: n.location, Reason: err}
	}

	// Commit the result to the original container that this constructor
	// was supplied to. The provided constructor is only used for a view of
	// the rest of the graph to instantiate the dependencies of this
	// container.
	receiver.Commit(n.s)
	n.called = true
	return nil
}

// stagingContainerWriter is a containerWriter that records the changes that
// would be made to a containerWriter and defers them until Commit is called.
type stagingContainerWriter struct {
	values map[key]reflect.Value
	groups map[key][]reflect.Value
}

var _ containerWriter = (*stagingContainerWriter)(nil)

func newStagingContainerWriter() *stagingContainerWriter {
	return &stagingContainerWriter{
		values: make(map[key]reflect.Value),
		groups: make(map[key][]reflect.Value),
	}
}

func (sr *stagingContainerWriter) setValue(name string, t reflect.Type, v reflect.Value) {
	sr.values[key{t: t, name: name}] = v
}

func (sr *stagingContainerWriter) setDecoratedValue(_ string, _ reflect.Type, _ reflect.Value) {
	digerror.BugPanicf("stagingContainerWriter.setDecoratedValue must never be called")
}

func (sr *stagingContainerWriter) submitGroupedValue(group string, t reflect.Type, v reflect.Value) {
	k := key{t: t, group: group}
	sr.groups[k] = append(sr.groups[k], v)
}

func (sr *stagingContainerWriter) submitDecoratedGroupedValue(_ string, _ reflect.Type, _ reflect.Value) {
	digerror.BugPanicf("stagingContainerWriter.submitDecoratedGroupedValue must never be called")
}

// Commit commits the received results to the provided containerWriter.
func (sr *stagingContainerWriter) Commit(cw containerWriter) {
	for k, v := range sr.values {
		cw.setValue(k.name, k.t, v)
	}

	for k, vs := range sr.groups {
		for _, v := range vs {
			cw.submitGroupedValue(k.group, k.t, v)
		}
	}
}
