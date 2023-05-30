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
	"math/rand"
	"reflect"

	"go.uber.org/dig/internal/dot"
)

const (
	_optionalTag         = "optional"
	_nameTag             = "name"
	_ignoreUnexportedTag = "ignore-unexported"
)

// Unique identification of an object in the graph.
type key struct {
	t reflect.Type

	// Only one of name or group will be set.
	name  string
	group string
}

func (k key) String() string {
	if k.name != "" {
		return fmt.Sprintf("%v[name=%q]", k.t, k.name)
	}
	if k.group != "" {
		return fmt.Sprintf("%v[group=%q]", k.t, k.group)
	}
	return k.t.String()
}

// Option configures a Container.
type Option interface {
	applyOption(*Container)
}

// Container is a directed acyclic graph of types and their dependencies.
// A Container is the root Scope that represents the top-level scoped
// directed acyclic graph of the dependencies.
type Container struct {
	// this is the "root" Scope that represents the
	// root of the scope tree.
	scope *Scope
}

// containerWriter provides write access to the Container's underlying data
// store.
type containerWriter interface {
	// setValue sets the value with the given name and type in the container.
	// If a value with the same name and type already exists, it will be
	// overwritten.
	setValue(name string, t reflect.Type, v reflect.Value)

	// setDecoratedValue sets a decorated value with the given name and type
	// in the container. If a decorated value with the same name and type already
	// exists, it will be overwritten.
	setDecoratedValue(name string, t reflect.Type, v reflect.Value)

	// submitGroupedValue submits a value to the value group with the provided
	// name.
	submitGroupedValue(name string, t reflect.Type, v reflect.Value)

	// submitDecoratedGroupedValue submits a decorated value to the value group
	// with the provided name.
	submitDecoratedGroupedValue(name string, t reflect.Type, v reflect.Value)
}

// containerStore provides access to the Container's underlying data store.
type containerStore interface {
	containerWriter

	// Adds a new graph node to the Container
	newGraphNode(w interface{}, orders map[*Scope]int)

	// Returns a slice containing all known types.
	knownTypes() []reflect.Type

	// Retrieves the value with the provided name and type, if any.
	getValue(name string, t reflect.Type) (v reflect.Value, ok bool)

	// Retrieves a decorated value with the provided name and type, if any.
	getDecoratedValue(name string, t reflect.Type) (v reflect.Value, ok bool)

	// Retrieves all values for the provided group and type.
	//
	// The order in which the values are returned is undefined.
	getValueGroup(name string, t reflect.Type) []reflect.Value

	// Retrieves all decorated values for the provided group and type, if any.
	getDecoratedValueGroup(name string, t reflect.Type) (reflect.Value, bool)

	// Returns the providers that can produce a value with the given name and
	// type.
	getValueProviders(name string, t reflect.Type) []provider

	// Returns the providers that can produce values for the given group and
	// type.
	getGroupProviders(name string, t reflect.Type) []provider

	// Returns the providers that can produce a value with the given name and
	// type across all the Scopes that are in effect of this containerStore.
	getAllValueProviders(name string, t reflect.Type) []provider

	// Returns the decorator that can decorate values for the given name and
	// type.
	getValueDecorator(name string, t reflect.Type) (decorator, bool)

	// Reutrns the decorator that can decorate values for the given group and
	// type.
	getGroupDecorator(name string, t reflect.Type) (decorator, bool)

	// Reports a list of stores (starting at this store) up to the root
	// store.
	storesToRoot() []containerStore

	createGraph() *dot.Graph

	// Returns invokerFn function to use when calling arguments.
	invoker() invokerFn
}

// New constructs a Container.
func New(opts ...Option) *Container {
	s := newScope()
	c := &Container{scope: s}

	for _, opt := range opts {
		opt.applyOption(c)
	}
	return c
}

// DeferAcyclicVerification is an Option to override the default behavior
// of container.Provide, deferring the dependency graph validation to no longer
// run after each call to container.Provide. The container will instead verify
// the graph on first `Invoke`.
//
// Applications adding providers to a container in a tight loop may experience
// performance improvements by initializing the container with this option.
func DeferAcyclicVerification() Option {
	return deferAcyclicVerificationOption{}
}

type deferAcyclicVerificationOption struct{}

func (deferAcyclicVerificationOption) String() string {
	return "DeferAcyclicVerification()"
}

func (deferAcyclicVerificationOption) applyOption(c *Container) {
	c.scope.deferAcyclicVerification = true
}

// RecoverFromPanics is an [Option] to recover from panics that occur while
// running functions given to the container. When set, recovered panics
// will be placed into a [PanicError], and returned at the invoke callsite.
// See [PanicError] for an example on how to handle panics with this option
// enabled, and distinguish them from errors.
func RecoverFromPanics() Option {
	return recoverFromPanicsOption{}
}

type recoverFromPanicsOption struct{}

func (recoverFromPanicsOption) String() string {
	return "RecoverFromPanics()"
}

func (recoverFromPanicsOption) applyOption(c *Container) {
	c.scope.recoverFromPanics = true
}

// Changes the source of randomness for the container.
//
// This will help provide determinism during tests.
func setRand(r *rand.Rand) Option {
	return setRandOption{r: r}
}

type setRandOption struct{ r *rand.Rand }

func (o setRandOption) String() string {
	return fmt.Sprintf("setRand(%p)", o.r)
}

func (o setRandOption) applyOption(c *Container) {
	c.scope.rand = o.r
}

// DryRun is an Option which, when set to true, disables invocation of functions supplied to
// Provide and Invoke. Use this to build no-op containers.
func DryRun(dry bool) Option {
	return dryRunOption(dry)
}

type dryRunOption bool

func (o dryRunOption) String() string {
	return fmt.Sprintf("DryRun(%v)", bool(o))
}

func (o dryRunOption) applyOption(c *Container) {
	if o {
		c.scope.invokerFn = dryInvoker
	} else {
		c.scope.invokerFn = defaultInvoker
	}
}

// invokerFn specifies how the container calls user-supplied functions.
type invokerFn func(fn reflect.Value, args []reflect.Value) (results []reflect.Value)

func defaultInvoker(fn reflect.Value, args []reflect.Value) []reflect.Value {
	return fn.Call(args)
}

// Generates zero values for results without calling the supplied function.
func dryInvoker(fn reflect.Value, _ []reflect.Value) []reflect.Value {
	ft := fn.Type()
	results := make([]reflect.Value, ft.NumOut())
	for i := 0; i < ft.NumOut(); i++ {
		results[i] = reflect.Zero(fn.Type().Out(i))
	}

	return results
}

// String representation of the entire Container
func (c *Container) String() string {
	return c.scope.String()
}

// Scope creates a child scope of the Container with the given name.
func (c *Container) Scope(name string, opts ...ScopeOption) *Scope {
	return c.scope.Scope(name, opts...)
}

type byTypeName []reflect.Type

func (bs byTypeName) Len() int {
	return len(bs)
}

func (bs byTypeName) Less(i int, j int) bool {
	return fmt.Sprint(bs[i]) < fmt.Sprint(bs[j])
}

func (bs byTypeName) Swap(i int, j int) {
	bs[i], bs[j] = bs[j], bs[i]
}

func shuffledCopy(rand *rand.Rand, items []reflect.Value) []reflect.Value {
	newItems := make([]reflect.Value, len(items))
	for i, j := range rand.Perm(len(items)) {
		newItems[i] = items[j]
	}
	return newItems
}
