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
	"bytes"
	"fmt"
	"reflect"
	"strings"

	"go.uber.org/dig/internal/digreflect"
	"go.uber.org/dig/internal/dot"
	"go.uber.org/dig/internal/graph"
)

// A ProvideOption modifies the default behavior of Provide.
type ProvideOption interface {
	applyProvideOption(*provideOptions)
}

type provideOptions struct {
	Name     string
	Group    string
	Info     *ProvideInfo
	As       []interface{}
	Location *digreflect.Func
	Exported bool
	Callback Callback
}

func (o *provideOptions) Validate() error {
	if len(o.Group) > 0 {
		if len(o.Name) > 0 {
			return newErrInvalidInput(
				fmt.Sprintf("cannot use named values with value groups: name:%q provided with group:%q", o.Name, o.Group), nil)
		}
	}

	// Names must be representable inside a backquoted string. The only
	// limitation for raw string literals as per
	// https://golang.org/ref/spec#raw_string_lit is that they cannot contain
	// backquotes.
	if strings.ContainsRune(o.Name, '`') {
		return newErrInvalidInput(
			fmt.Sprintf("invalid dig.Name(%q): names cannot contain backquotes", o.Name), nil)
	}
	if strings.ContainsRune(o.Group, '`') {
		return newErrInvalidInput(
			fmt.Sprintf("invalid dig.Group(%q): group names cannot contain backquotes", o.Group), nil)
	}

	for _, i := range o.As {
		t := reflect.TypeOf(i)

		if t == nil {
			return newErrInvalidInput("invalid dig.As(nil): argument must be a pointer to an interface", nil)
		}

		if t.Kind() != reflect.Ptr {
			return newErrInvalidInput(
				fmt.Sprintf("invalid dig.As(%v): argument must be a pointer to an interface", t), nil)
		}

		pointingTo := t.Elem()
		if pointingTo.Kind() != reflect.Interface {
			return newErrInvalidInput(
				fmt.Sprintf("invalid dig.As(*%v): argument must be a pointer to an interface", pointingTo), nil)
		}
	}
	return nil
}

// Name is a ProvideOption that specifies that all values produced by a
// constructor should have the given name. See also the package documentation
// about Named Values.
//
// Given,
//
//	func NewReadOnlyConnection(...) (*Connection, error)
//	func NewReadWriteConnection(...) (*Connection, error)
//
// The following will provide two connections to the container: one under the
// name "ro" and the other under the name "rw".
//
//	c.Provide(NewReadOnlyConnection, dig.Name("ro"))
//	c.Provide(NewReadWriteConnection, dig.Name("rw"))
//
// This option cannot be provided for constructors which produce result
// objects.
func Name(name string) ProvideOption {
	return provideNameOption(name)
}

type provideNameOption string

func (o provideNameOption) String() string {
	return fmt.Sprintf("Name(%q)", string(o))
}

func (o provideNameOption) applyProvideOption(opt *provideOptions) {
	opt.Name = string(o)
}

// Group is a ProvideOption that specifies that all values produced by a
// constructor should be added to the specified group. See also the package
// documentation about Value Groups.
//
// This option cannot be provided for constructors which produce result
// objects.
func Group(group string) ProvideOption {
	return provideGroupOption(group)
}

type provideGroupOption string

func (o provideGroupOption) String() string {
	return fmt.Sprintf("Group(%q)", string(o))
}

func (o provideGroupOption) applyProvideOption(opt *provideOptions) {
	opt.Group = string(o)
}

// ID is a unique integer representing the constructor node in the dependency graph.
type ID int

// ProvideInfo provides information about the constructor's inputs and outputs
// types as strings, as well as the ID of the constructor supplied to the Container.
// It contains ID for the constructor, as well as slices of Input and Output types,
// which are Stringers that report the types of the parameters and results respectively.
type ProvideInfo struct {
	ID      ID
	Inputs  []*Input
	Outputs []*Output
}

// Input contains information on an input parameter of a function.
type Input struct {
	t           reflect.Type
	optional    bool
	name, group string
}

func (i *Input) String() string {
	toks := make([]string, 0, 3)
	t := i.t.String()
	if i.optional {
		toks = append(toks, "optional")
	}
	if i.name != "" {
		toks = append(toks, fmt.Sprintf("name = %q", i.name))
	}
	if i.group != "" {
		toks = append(toks, fmt.Sprintf("group = %q", i.group))
	}

	if len(toks) == 0 {
		return t
	}
	return fmt.Sprintf("%v[%v]", t, strings.Join(toks, ", "))
}

// Output contains information on an output produced by a function.
type Output struct {
	t           reflect.Type
	name, group string
}

func (o *Output) String() string {
	toks := make([]string, 0, 2)
	t := o.t.String()
	if o.name != "" {
		toks = append(toks, fmt.Sprintf("name = %q", o.name))
	}
	if o.group != "" {
		toks = append(toks, fmt.Sprintf("group = %q", o.group))
	}

	if len(toks) == 0 {
		return t
	}
	return fmt.Sprintf("%v[%v]", t, strings.Join(toks, ", "))
}

// FillProvideInfo is a ProvideOption that writes info on what Dig was able to get
// out of the provided constructor into the provided ProvideInfo.
func FillProvideInfo(info *ProvideInfo) ProvideOption {
	return fillProvideInfoOption{info: info}
}

type fillProvideInfoOption struct{ info *ProvideInfo }

func (o fillProvideInfoOption) String() string {
	return fmt.Sprintf("FillProvideInfo(%p)", o.info)
}

func (o fillProvideInfoOption) applyProvideOption(opts *provideOptions) {
	opts.Info = o.info
}

// As is a ProvideOption that specifies that the value produced by the
// constructor implements one or more other interfaces and is provided
// to the container as those interfaces.
//
// As expects one or more pointers to the implemented interfaces. Values
// produced by constructors will be then available in the container as
// implementations of all of those interfaces, but not as the value itself.
//
// For example, the following will make io.Reader and io.Writer available
// in the container, but not buffer.
//
//	c.Provide(newBuffer, dig.As(new(io.Reader), new(io.Writer)))
//
// That is, the above is equivalent to the following.
//
//	c.Provide(func(...) (io.Reader, io.Writer) {
//	  b := newBuffer(...)
//	  return b, b
//	})
//
// If used with dig.Name, the type produced by the constructor and the types
// specified with dig.As will all use the same name. For example,
//
//	c.Provide(newFile, dig.As(new(io.Reader)), dig.Name("temp"))
//
// The above is equivalent to the following.
//
//	type Result struct {
//	  dig.Out
//
//	  Reader io.Reader `name:"temp"`
//	}
//
//	c.Provide(func(...) Result {
//	  f := newFile(...)
//	  return Result{
//	    Reader: f,
//	  }
//	})
//
// This option cannot be provided for constructors which produce result
// objects.
func As(i ...interface{}) ProvideOption {
	return provideAsOption(i)
}

type provideAsOption []interface{}

func (o provideAsOption) String() string {
	buf := bytes.NewBufferString("As(")
	for i, iface := range o {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(reflect.TypeOf(iface).Elem().String())
	}
	buf.WriteString(")")
	return buf.String()
}

func (o provideAsOption) applyProvideOption(opts *provideOptions) {
	opts.As = append(opts.As, o...)
}

// LocationForPC is a ProvideOption which specifies an alternate function program
// counter address to be used for debug information. The package, name, file and
// line number of this alternate function address will be used in error messages
// and DOT graphs. This option is intended to be used with functions created
// with the reflect.MakeFunc method whose error messages are otherwise hard to
// understand
func LocationForPC(pc uintptr) ProvideOption {
	return provideLocationOption{
		loc: digreflect.InspectFuncPC(pc),
	}
}

type provideLocationOption struct{ loc *digreflect.Func }

func (o provideLocationOption) String() string {
	return fmt.Sprintf("LocationForPC(%v)", o.loc)
}

func (o provideLocationOption) applyProvideOption(opts *provideOptions) {
	opts.Location = o.loc
}

// Export is a ProvideOption which specifies that the provided function should
// be made available to all Scopes available in the application, regardless
// of which Scope it was provided from. By default, it is false.
//
// For example,
//
//	c := New()
//	s1 := c.Scope("child 1")
//	s2:= c.Scope("child 2")
//	s1.Provide(func() *bytes.Buffer { ... })
//
// does not allow the constructor returning *bytes.Buffer to be made available to
// the root Container c or its sibling Scope s2.
//
// With Export, you can make this constructor available to all the Scopes:
//
//	s1.Provide(func() *bytes.Buffer { ... }, Export(true))
func Export(export bool) ProvideOption {
	return provideExportOption{exported: export}
}

type provideExportOption struct{ exported bool }

func (o provideExportOption) String() string {
	return fmt.Sprintf("Export(%v)", o.exported)
}

func (o provideExportOption) applyProvideOption(opts *provideOptions) {
	opts.Exported = o.exported
}

// provider encapsulates a user-provided constructor.
type provider interface {
	// ID is a unique numerical identifier for this provider.
	ID() dot.CtorID

	// Order reports the order of this provider in the graphHolder.
	// This value is usually returned by the graphHolder.NewNode method.
	Order(*Scope) int

	// Location returns where this constructor was defined.
	Location() *digreflect.Func

	// ParamList returns information about the direct dependencies of this
	// constructor.
	ParamList() paramList

	// ResultList returns information about the values produced by this
	// constructor.
	ResultList() resultList

	// Calls the underlying constructor, reading values from the
	// containerStore as needed.
	//
	// The values produced by this provider should be submitted into the
	// containerStore.
	Call(containerStore) error

	CType() reflect.Type

	OrigScope() *Scope
}

// Provide teaches the container how to build values of one or more types and
// expresses their dependencies.
//
// The first argument of Provide is a function that accepts zero or more
// parameters and returns one or more results. The function may optionally
// return an error to indicate that it failed to build the value. This
// function will be treated as the constructor for all the types it returns.
// This function will be called AT MOST ONCE when a type produced by it, or a
// type that consumes this function's output, is requested via Invoke. If the
// same types are requested multiple times, the previously produced value will
// be reused.
//
// Provide accepts argument types or dig.In structs as dependencies, and
// separate return values or dig.Out structs for results.
func (c *Container) Provide(constructor interface{}, opts ...ProvideOption) error {
	return c.scope.Provide(constructor, opts...)
}

// Provide teaches the Scope how to build values of one or more types and
// expresses their dependencies.
//
// The first argument of Provide is a function that accepts zero or more
// parameters and returns one or more results. The function may optionally
// return an error to indicate that it failed to build the value. This
// function will be treated as the constructor for all the types it returns.
// This function will be called AT MOST ONCE when a type produced by it, or a
// type that consumes this function's output, is requested via Invoke. If the
// same types are requested multiple times, the previously produced value will
// be reused.
//
// Provide accepts argument types or dig.In structs as dependencies, and
// separate return values or dig.Out structs for results.
//
// When a constructor is Provided to a Scope, it will propagate this to any
// Scopes that are descendents, but not ancestors of this Scope.
// To provide a constructor to all the Scopes available, provide it to
// Container, which is the root Scope.
func (s *Scope) Provide(constructor interface{}, opts ...ProvideOption) error {
	ctype := reflect.TypeOf(constructor)
	if ctype == nil {
		return newErrInvalidInput("can't provide an untyped nil", nil)
	}
	if ctype.Kind() != reflect.Func {
		return newErrInvalidInput(
			fmt.Sprintf("must provide constructor function, got %v (type %v)", constructor, ctype), nil)
	}

	var options provideOptions
	for _, o := range opts {
		o.applyProvideOption(&options)
	}
	if err := options.Validate(); err != nil {
		return err
	}

	if err := s.provide(constructor, options); err != nil {
		var errFunc *digreflect.Func
		if options.Location == nil {
			errFunc = digreflect.InspectFunc(constructor)
		} else {
			errFunc = options.Location
		}

		return errProvide{
			Func:   errFunc,
			Reason: err,
		}
	}
	return nil
}

func (s *Scope) provide(ctor interface{}, opts provideOptions) (err error) {
	// If Export option is provided to the constructor, this should be injected to the
	// root-level Scope (Container) to allow it to propagate to all other Scopes.
	origScope := s
	if opts.Exported {
		s = s.rootScope()
	}

	// For all scopes affected by this change,
	// take a snapshot of the current graph state before
	// we start making changes to it as we may need to
	// undo them upon encountering errors.
	allScopes := s.appendSubscopes(nil)
	for _, s := range allScopes {
		s := s
		s.gh.Snapshot()
		defer func() {
			if err != nil {
				s.gh.Rollback()
			}
		}()
	}

	n, err := newConstructorNode(
		ctor,
		s,
		origScope,
		constructorOptions{
			ResultName:  opts.Name,
			ResultGroup: opts.Group,
			ResultAs:    opts.As,
			Location:    opts.Location,
			Callback:    opts.Callback,
		},
	)
	if err != nil {
		return err
	}

	keys, err := s.findAndValidateResults(n.ResultList())
	if err != nil {
		return err
	}

	ctype := reflect.TypeOf(ctor)
	if len(keys) == 0 {
		return newErrInvalidInput(
			fmt.Sprintf("%v must provide at least one non-error type", ctype), nil)
	}

	oldProviders := make(map[key][]*constructorNode)
	for k := range keys {
		// Cache old providers before running cycle detection.
		oldProviders[k] = s.providers[k]
		s.providers[k] = append(s.providers[k], n)
	}

	for _, s := range allScopes {
		s.isVerifiedAcyclic = false
		if s.deferAcyclicVerification {
			continue
		}
		if ok, cycle := graph.IsAcyclic(s.gh); !ok {
			// When a cycle is detected, recover the old providers to reset
			// the providers map back to what it was before this node was
			// introduced.
			for k, ops := range oldProviders {
				s.providers[k] = ops
			}

			return newErrInvalidInput("this function introduces a cycle", s.cycleDetectedError(cycle))
		}
		s.isVerifiedAcyclic = true
	}

	s.nodes = append(s.nodes, n)

	// Record introspection info for caller if Info option is specified
	if info := opts.Info; info != nil {
		params := n.ParamList().DotParam()
		results := n.ResultList().DotResult()

		info.ID = (ID)(n.id)
		info.Inputs = make([]*Input, len(params))
		info.Outputs = make([]*Output, len(results))

		for i, param := range params {
			info.Inputs[i] = &Input{
				t:        param.Type,
				optional: param.Optional,
				name:     param.Name,
				group:    param.Group,
			}
		}

		for i, res := range results {
			info.Outputs[i] = &Output{
				t:     res.Type,
				name:  res.Name,
				group: res.Group,
			}
		}
	}
	return nil
}

// Builds a collection of all result types produced by this constructor.
func (s *Scope) findAndValidateResults(rl resultList) (map[key]struct{}, error) {
	var err error
	keyPaths := make(map[key]string)
	walkResult(rl, connectionVisitor{
		s:        s,
		err:      &err,
		keyPaths: keyPaths,
	})

	if err != nil {
		return nil, err
	}

	keys := make(map[key]struct{}, len(keyPaths))
	for k := range keyPaths {
		keys[k] = struct{}{}
	}
	return keys, nil
}

// Visits the results of a node and compiles a collection of all the keys
// produced by that node.
type connectionVisitor struct {
	s *Scope

	// If this points to a non-nil value, we've already encountered an error
	// and should stop traversing.
	err *error

	// Map of keys provided to path that provided this. The path is a string
	// documenting which positional return value or dig.Out attribute is
	// providing this particular key.
	//
	// For example, "[0].Foo" indicates that the value was provided by the Foo
	// attribute of the dig.Out returned as the first result of the
	// constructor.
	keyPaths map[key]string

	// We track the path to the current result here. For example, this will
	// be, ["[1]", "Foo", "Bar"] when we're visiting Bar in,
	//
	//   func() (io.Writer, struct {
	//     dig.Out
	//
	//     Foo struct {
	//       dig.Out
	//
	//       Bar io.Reader
	//     }
	//   })
	currentResultPath []string
}

func (cv connectionVisitor) AnnotateWithField(f resultObjectField) resultVisitor {
	cv.currentResultPath = append(cv.currentResultPath, f.FieldName)
	return cv
}

func (cv connectionVisitor) AnnotateWithPosition(i int) resultVisitor {
	cv.currentResultPath = append(cv.currentResultPath, fmt.Sprintf("[%d]", i))
	return cv
}

func (cv connectionVisitor) Visit(res result) resultVisitor {
	// Already failed. Stop looking.
	if *cv.err != nil {
		return nil
	}

	path := strings.Join(cv.currentResultPath, ".")

	switch r := res.(type) {

	case resultSingle:
		k := key{name: r.Name, t: r.Type}

		if err := cv.checkKey(k, path); err != nil {
			*cv.err = err
			return nil
		}
		for _, asType := range r.As {
			k := key{name: r.Name, t: asType}
			if err := cv.checkKey(k, path); err != nil {
				*cv.err = err
				return nil
			}
		}

	case resultGrouped:
		// we don't really care about the path for this since conflicts are
		// okay for group results. We'll track it for the sake of having a
		// value there.
		k := key{group: r.Group, t: r.Type}
		cv.keyPaths[k] = path
		for _, asType := range r.As {
			k := key{group: r.Group, t: asType}
			cv.keyPaths[k] = path
		}
	}

	return cv
}

func (cv connectionVisitor) checkKey(k key, path string) error {
	defer func() { cv.keyPaths[k] = path }()
	if conflict, ok := cv.keyPaths[k]; ok {
		return newErrInvalidInput(fmt.Sprintf("cannot provide %v from %v", k, path),
			newErrInvalidInput(fmt.Sprintf("already provided by %v", conflict), nil))
	}
	if ps := cv.s.providers[k]; len(ps) > 0 {
		cons := make([]string, len(ps))
		for i, p := range ps {
			cons[i] = fmt.Sprint(p.Location())
		}

		return newErrInvalidInput(fmt.Sprintf("cannot provide %v from %v", k, path),
			newErrInvalidInput(fmt.Sprintf("already provided by %v", strings.Join(cons, "; ")), nil))
	}
	return nil
}
