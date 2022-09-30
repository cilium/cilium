// Copyright (c) 2020-2021 Uber Technologies, Inc.
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
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"go.uber.org/dig"
	"go.uber.org/fx/internal/fxreflect"
)

// Annotated annotates a constructor provided to Fx with additional options.
//
// For example,
//
//	func NewReadOnlyConnection(...) (*Connection, error)
//
//	fx.Provide(fx.Annotated{
//	  Name: "ro",
//	  Target: NewReadOnlyConnection,
//	})
//
// Is equivalent to,
//
//	type result struct {
//	  fx.Out
//
//	  Connection *Connection `name:"ro"`
//	}
//
//	fx.Provide(func(...) (result, error) {
//	  conn, err := NewReadOnlyConnection(...)
//	  return result{Connection: conn}, err
//	})
//
// Annotated cannot be used with constructors which produce fx.Out objects.
//
// When used with fx.Supply, the target is a value rather than a constructor function.
type Annotated struct {
	// If specified, this will be used as the name for all non-error values returned
	// by the constructor. For more information on named values, see the documentation
	// for the fx.Out type.
	//
	// A name option may not be provided if a group option is provided.
	Name string

	// If specified, this will be used as the group name for all non-error values returned
	// by the constructor. For more information on value groups, see the package documentation.
	//
	// A group option may not be provided if a name option is provided.
	//
	// Similar to group tags, the group name may be followed by a `,flatten`
	// option to indicate that each element in the slice returned by the
	// constructor should be injected into the value group individually.
	Group string

	// Target is the constructor or value being annotated with fx.Annotated.
	Target interface{}
}

func (a Annotated) String() string {
	var fields []string
	if len(a.Name) > 0 {
		fields = append(fields, fmt.Sprintf("Name: %q", a.Name))
	}
	if len(a.Group) > 0 {
		fields = append(fields, fmt.Sprintf("Group: %q", a.Group))
	}
	if a.Target != nil {
		fields = append(fields, fmt.Sprintf("Target: %v", fxreflect.FuncName(a.Target)))
	}
	return fmt.Sprintf("fx.Annotated{%v}", strings.Join(fields, ", "))
}

// field used for embedding fx.Out type in generated struct.
var _outAnnotationField = reflect.StructField{
	Name:      "Out",
	Type:      reflect.TypeOf(Out{}),
	Anonymous: true,
}

// Annotation can be passed to Annotate(f interface{}, anns ...Annotation)
// for annotating the parameter and result types of a function.
type Annotation interface {
	apply(*annotated) error
}

var (
	_typeOfError reflect.Type = reflect.TypeOf((*error)(nil)).Elem()
	_nilError                 = reflect.Zero(_typeOfError)
)

// annotationError is a wrapper for an error that was encountered while
// applying annotation to a function. It contains the specific error
// that it encountered as well as the target interface that was attempted
// to be annotated.
type annotationError struct {
	target interface{}
	err    error
}

func (e *annotationError) Error() string {
	return e.err.Error()
}

type paramTagsAnnotation struct {
	tags []string
}

var _ Annotation = paramTagsAnnotation{}

// Given func(T1, T2, T3, ..., TN), this generates a type roughly
// equivalent to,
//
//   struct {
//     fx.In
//
//     Field1 T1 `$tags[0]`
//     Field2 T2 `$tags[1]`
//     ...
//     FieldN TN `$tags[N-1]`
//   }
//
// If there has already been a ParamTag that was applied, this
// will return an error.

func (pt paramTagsAnnotation) apply(ann *annotated) error {
	if len(ann.ParamTags) > 0 {
		return errors.New("cannot apply more than one line of ParamTags")
	}
	ann.ParamTags = pt.tags
	return nil
}

// ParamTags is an Annotation that annotates the parameter(s) of a function.
// When multiple tags are specified, each tag is mapped to the corresponding
// positional parameter.
func ParamTags(tags ...string) Annotation {
	return paramTagsAnnotation{tags}
}

type resultTagsAnnotation struct {
	tags []string
}

var _ Annotation = resultTagsAnnotation{}

// Given func(T1, T2, T3, ..., TN), this generates a type roughly
// equivalent to,
//
//	struct {
//	  fx.Out
//
//	  Field1 T1 `$tags[0]`
//	  Field2 T2 `$tags[1]`
//	  ...
//	  FieldN TN `$tags[N-1]`
//	}
//
// If there has already been a ResultTag that was applied, this
// will return an error.
func (rt resultTagsAnnotation) apply(ann *annotated) error {
	if len(ann.ResultTags) > 0 {
		return errors.New("cannot apply more than one line of ResultTags")
	}
	ann.ResultTags = rt.tags
	return nil
}

// ResultTags is an Annotation that annotates the result(s) of a function.
// When multiple tags are specified, each tag is mapped to the corresponding
// positional result.
func ResultTags(tags ...string) Annotation {
	return resultTagsAnnotation{tags}
}

type _lifecycleHookAnnotationType int

const (
	_unknownHookType _lifecycleHookAnnotationType = iota
	_onStartHookType
	_onStopHookType
)

type lifecycleHookAnnotation struct {
	Type   _lifecycleHookAnnotationType
	Target interface{}
}

var _ Annotation = (*lifecycleHookAnnotation)(nil)

func (la *lifecycleHookAnnotation) String() string {
	name := "UnknownHookAnnotation"
	switch la.Type {
	case _onStartHookType:
		name = _onStartHook
	case _onStopHookType:
		name = _onStopHook
	}
	return name
}

func (la *lifecycleHookAnnotation) apply(ann *annotated) error {
	if la.Target == nil {
		return fmt.Errorf(
			"cannot use nil function for %q hook annotation",
			la,
		)
	}

	for _, h := range ann.Hooks {
		if la.Type == h.Type {
			return fmt.Errorf(
				"cannot apply more than one %q hook annotation",
				la,
			)
		}
	}

	ft := reflect.TypeOf(la.Target)

	if ft.Kind() != reflect.Func {
		return fmt.Errorf(
			"must provide function for %q hook, got %v (%T)",
			la,
			la.Target,
			la.Target,
		)
	}

	if ft.NumIn() < 1 || ft.In(0) != _typeOfContext {
		return fmt.Errorf(
			"first argument of hook must be context.Context, got %v (%T)",
			la.Target,
			la.Target,
		)
	}

	hasOut := ft.NumOut() == 1
	returnsErr := hasOut && ft.Out(0) == _typeOfError

	if !hasOut || !returnsErr {
		return fmt.Errorf(
			"hooks must return only an error type, got %v (%T)",
			la.Target,
			la.Target,
		)
	}

	if ft.IsVariadic() {
		return fmt.Errorf(
			"hooks must not accept variatic parameters, got %v (%T)",
			la.Target,
			la.Target,
		)
	}

	ann.Hooks = append(ann.Hooks, la)
	return nil
}

var (
	_typeOfLifecycle reflect.Type = reflect.TypeOf((*Lifecycle)(nil)).Elem()
	_typeOfContext   reflect.Type = reflect.TypeOf((*context.Context)(nil)).Elem()
)

type valueResolver func(reflect.Value, int) reflect.Value

func (la *lifecycleHookAnnotation) resolveMap(results []reflect.Type) (
	resultMap map[reflect.Type]valueResolver,
) {
	// index the constructor results by type and position to allow
	// for us to omit these from the in types that must be injected,
	// and to allow us to interleave constructor results
	// into our hook arguments.
	resultMap = make(map[reflect.Type]valueResolver, len(results))

	for _, r := range results {
		resultMap[r] = func(v reflect.Value, pos int) (value reflect.Value) {
			return v
		}
	}

	return
}

func (la *lifecycleHookAnnotation) resolveLifecycleParamField(
	param reflect.Value,
	n int,
) (
	value reflect.Value,
) {
	if param.Kind() == reflect.Struct {
		if n <= param.NumField() {
			value = param.FieldByName(fmt.Sprintf("Field%d", n))
		}
	}

	return value
}

func (la *lifecycleHookAnnotation) parameters(results ...reflect.Type) (
	in reflect.Type,
	argmap func(
		args []reflect.Value,
	) (Lifecycle, []reflect.Value),
) {
	resultMap := la.resolveMap(results)

	// hook functions require a lifecycle, and it should be injected
	params := []reflect.StructField{
		{
			Name:      "In",
			Type:      _typeOfIn,
			Anonymous: true,
		},
		{
			Name: "Lifecycle",
			Type: _typeOfLifecycle,
		},
	}

	type argSource struct {
		pos     int
		result  bool
		resolve valueResolver
	}

	ft := reflect.TypeOf(la.Target)
	resolverIdx := make([]argSource, 1)

	for i := 1; i < ft.NumIn(); i++ {
		t := ft.In(i)
		result, isProvidedByResults := resultMap[t]

		if isProvidedByResults {
			resolverIdx = append(resolverIdx, argSource{
				pos:     i,
				result:  true,
				resolve: result,
			})
			continue
		}

		field := reflect.StructField{
			Name: fmt.Sprintf("Field%d", i),
			Type: t,
		}
		params = append(params, field)

		resolverIdx = append(resolverIdx, argSource{
			pos:     i,
			resolve: la.resolveLifecycleParamField,
		})
	}

	in = reflect.StructOf(params)

	argmap = func(
		args []reflect.Value,
	) (lc Lifecycle, remapped []reflect.Value) {
		remapped = make([]reflect.Value, ft.NumIn())

		if len(args) != 0 {
			var (
				results reflect.Value
				p       = args[0]
			)

			if len(args) > 1 {
				results = args[1]
			}

			lc, _ = p.FieldByName("Lifecycle").Interface().(Lifecycle)
			for i := 1; i < ft.NumIn(); i++ {
				resolver := resolverIdx[i]
				source := p
				if resolver.result {
					source = results
				}
				remapped[i] = resolver.resolve(source, i)
			}
		}
		return
	}
	return
}

func (la *lifecycleHookAnnotation) buildHook(fn func(context.Context) error) (hook Hook) {
	switch la.Type {
	case _onStartHookType:
		hook.OnStart = fn
	case _onStopHookType:
		hook.OnStop = fn
	}

	return
}

func (la *lifecycleHookAnnotation) Build(results ...reflect.Type) reflect.Value {
	in, paramMap := la.parameters(results...)
	params := []reflect.Type{in}
	for _, r := range results {
		if r != _typeOfError {
			params = append(params, r)
		}
	}

	origFn := reflect.ValueOf(la.Target)
	newFnType := reflect.FuncOf(params, nil, false)
	newFn := reflect.MakeFunc(newFnType, func(args []reflect.Value) []reflect.Value {
		var lc Lifecycle
		lc, args = paramMap(args)
		hookFn := func(ctx context.Context) (err error) {
			args[0] = reflect.ValueOf(ctx)

			results := origFn.Call(args)
			if len(results) > 0 && results[0].Type() == _typeOfError {
				err, _ = results[0].Interface().(error)
			}

			return
		}

		lc.Append(la.buildHook(hookFn))
		return []reflect.Value{}
	})

	return newFn
}

// OnStart is an Annotation that appends an OnStart Hook to the application
// Lifecycle when that function is called. This provides a way to create
// Lifecycle OnStart (see Lifecycle type documentation) hooks without building a
// function that takes a dependency on the Lifecycle type.
//
//	fx.Annotate(
//	  NewServer,
//	  fx.OnStart(func(ctx context.Context, server Server) error {
//	      return server.Listen(ctx)
//	  }),
//	)
//
// Which is functionally the same as:
//
//	 fx.Provide(
//	   func(lifecycle fx.Lifecycle, p Params) Server {
//	     server := NewServer(p)
//	     lifecycle.Append(fx.Hook{
//		      OnStart: func(ctx context.Context) error {
//			    return server.Listen(ctx)
//		      },
//	     })
//	   }
//	 )
//
// Only one OnStart annotation may be applied to a given function at a time,
// however functions may be annotated with other types of lifecylce Hooks, such
// as OnStop.
func OnStart(onStart interface{}) Annotation {
	return &lifecycleHookAnnotation{
		Type:   _onStartHookType,
		Target: onStart,
	}
}

// OnStop is an Annotation that appends an OnStop Hook to the application
// Lifecycle when that function is called. This provides a way to create
// Lifecycle OnStop (see Lifecycle type documentation) hooks without building a
// function that takes a dependency on the Lifecycle type.
//
//	fx.Annotate(
//	  NewServer,
//	  fx.OnStop(func(ctx context.Context, server Server) error {
//	      return server.Shutdown(ctx)
//	  }),
//	)
//
// Which is functionally the same as:
//
//	 fx.Provide(
//	   func(lifecycle fx.Lifecycle, p Params) Server {
//	     server := NewServer(p)
//	     lifecycle.Append(fx.Hook{
//		      OnStart: func(ctx context.Context) error {
//			    return server.Shutdown(ctx)
//		      },
//	     })
//	   }
//	 )
//
// Only one OnStop annotation may be applied to a given function at a time,
// however functions may be annotated with other types of lifecylce Hooks, such
// as OnStart.
func OnStop(onStop interface{}) Annotation {
	return &lifecycleHookAnnotation{
		Type:   _onStopHookType,
		Target: onStop,
	}
}

type asAnnotation struct {
	targets []interface{}
}

var _ Annotation = asAnnotation{}

// As is an Annotation that annotates the result of a function (i.e. a
// constructor) to be provided as another interface.
//
// For example, the following code specifies that the return type of
// bytes.NewBuffer (bytes.Buffer) should be provided as io.Writer type:
//
//	fx.Provide(
//	  fx.Annotate(bytes.NewBuffer(...), fx.As(new(io.Writer)))
//	)
//
// In other words, the code above is equivalent to:
//
//	fx.Provide(func() io.Writer {
//	  return bytes.NewBuffer()
//	  // provides io.Writer instead of *bytes.Buffer
//	})
//
// Note that the bytes.Buffer type is provided as an io.Writer type, so this
// constructor does NOT provide both bytes.Buffer and io.Writer type; it just
// provides io.Writer type.
//
// When multiple values are returned by the annotated function, each type
// gets mapped to corresponding positional result of the annotated function.
//
// For example,
//
//	func a() (bytes.Buffer, bytes.Buffer) {
//	  ...
//	}
//	fx.Provide(
//	  fx.Annotate(a, fx.As(new(io.Writer), new(io.Reader)))
//	)
//
// Is equivalent to,
//
//	fx.Provide(func() (io.Writer, io.Reader) {
//	  w, r := a()
//	  return w, r
//	}
func As(interfaces ...interface{}) Annotation {
	return asAnnotation{interfaces}
}

func (at asAnnotation) apply(ann *annotated) error {
	types := make([]reflect.Type, len(at.targets))
	for i, typ := range at.targets {
		t := reflect.TypeOf(typ)
		if t.Kind() != reflect.Ptr || t.Elem().Kind() != reflect.Interface {
			return fmt.Errorf("fx.As: argument must be a pointer to an interface: got %v", t)
		}
		t = t.Elem()
		types[i] = t
	}

	ann.As = append(ann.As, types)
	return nil
}

type annotated struct {
	Target     interface{}
	ParamTags  []string
	ResultTags []string
	As         [][]reflect.Type
	FuncPtr    uintptr
	Hooks      []*lifecycleHookAnnotation
}

func (ann annotated) String() string {
	var sb strings.Builder
	sb.WriteString("fx.Annotate(")
	sb.WriteString(fxreflect.FuncName(ann.Target))
	if tags := ann.ParamTags; len(tags) > 0 {
		fmt.Fprintf(&sb, ", fx.ParamTags(%q)", tags)
	}
	if tags := ann.ResultTags; len(tags) > 0 {
		fmt.Fprintf(&sb, ", fx.ResultTags(%q)", tags)
	}
	if as := ann.As; len(as) > 0 {
		fmt.Fprintf(&sb, ", fx.As(%v)", as)
	}
	return sb.String()
}

// Build builds and returns a constructor based on fx.In/fx.Out params and
// results wrapping the original constructor passed to fx.Annotate.
func (ann *annotated) Build() (interface{}, error) {
	ft := reflect.TypeOf(ann.Target)
	if ft.Kind() != reflect.Func {
		return nil, fmt.Errorf("must provide constructor function, got %v (%T)", ann.Target, ann.Target)
	}

	if err := ann.typeCheckOrigFn(); err != nil {
		return nil, fmt.Errorf("invalid annotation function %T: %w", ann.Target, err)
	}

	resultTypes, remapResults, err := ann.results()
	if err != nil {
		return nil, err
	}
	paramTypes, remapParams, hookParams := ann.parameters(resultTypes...)

	hookFns := make([]reflect.Value, len(ann.Hooks))
	for i, builder := range ann.Hooks {
		if hookFn := builder.Build(resultTypes...); !hookFn.IsZero() {
			hookFns[i] = hookFn
		}
	}

	newFnType := reflect.FuncOf(paramTypes, resultTypes, false)
	origFn := reflect.ValueOf(ann.Target)
	ann.FuncPtr = origFn.Pointer()

	newFn := reflect.MakeFunc(newFnType, func(args []reflect.Value) []reflect.Value {
		origArgs := make([]reflect.Value, len(args))
		copy(origArgs, args)
		args = remapParams(args)
		var results []reflect.Value
		if ft.IsVariadic() {
			results = origFn.CallSlice(args)
		} else {
			results = origFn.Call(args)
		}
		results = remapResults(results)

		// if the number of results is greater than zero and the final result
		// is a non-nil error, do not execute hook installers
		hasErrorResult := len(results) > 0 && results[len(results)-1].Type() == _typeOfError
		if hasErrorResult {
			if err, ok := results[len(results)-1].Interface().(error); ok && err != nil {
				return results
			}
		}

		for i, hookFn := range hookFns {
			hookArgs := hookParams(i, origArgs, results)
			hookFn.Call(hookArgs)
		}

		return results
	})

	return newFn.Interface(), nil
}

// checks whether the target function is either
// returning an fx.Out struct or an taking in a
// fx.In struct as a parameter.
func (ann *annotated) typeCheckOrigFn() error {
	ft := reflect.TypeOf(ann.Target)
	for i := 0; i < ft.NumOut(); i++ {
		ot := ft.Out(i)
		if ot.Kind() != reflect.Struct {
			continue
		}
		if dig.IsOut(reflect.New(ft.Out(i)).Elem().Interface()) {
			return errors.New("fx.Out structs cannot be annotated")
		}
	}

	for i := 0; i < ft.NumIn(); i++ {
		it := ft.In(i)
		if it.Kind() != reflect.Struct {
			continue
		}
		if dig.IsIn(reflect.New(ft.In(i)).Elem().Interface()) {
			return errors.New("fx.In structs cannot be annotated")
		}
	}
	return nil
}

// parameters returns the type for the parameters of the annotated function,
// and a function that maps the arguments of the annotated function
// back to the arguments of the target function and a function that maps
// values to any lifecycle hook annotations. It accepts a variactic set
// of reflect.Type which allows for omitting any resulting constructor types
// from required parameters for annotation hooks.
func (ann *annotated) parameters(results ...reflect.Type) (
	types []reflect.Type,
	remap func([]reflect.Value) []reflect.Value,
	hookValueMap func(int, []reflect.Value, []reflect.Value) []reflect.Value,
) {
	ft := reflect.TypeOf(ann.Target)

	types = make([]reflect.Type, ft.NumIn())
	for i := 0; i < ft.NumIn(); i++ {
		types[i] = ft.In(i)
	}

	// No parameter annotations. Return the original types
	// and an identity function.
	if len(ann.ParamTags) == 0 && !ft.IsVariadic() && len(ann.Hooks) == 0 {
		return types, func(args []reflect.Value) []reflect.Value {
			return args
		}, nil
	}

	// Turn parameters into an fx.In struct.
	inFields := []reflect.StructField{
		{
			Name:      "In",
			Type:      reflect.TypeOf(In{}),
			Anonymous: true,
		},
	}

	for i, t := range types {
		field := reflect.StructField{
			Name: fmt.Sprintf("Field%d", i),
			Type: t,
		}

		if i < len(ann.ParamTags) {
			field.Tag = reflect.StructTag(ann.ParamTags[i])
		} else if i == ft.NumIn()-1 && ft.IsVariadic() {
			// If a variadic argument is unannotated, mark it optional,
			// so that just wrapping a function in fx.Annotate does not
			// suddenly introduce a required []arg dependency.
			field.Tag = reflect.StructTag(`optional:"true"`)
		}

		inFields = append(inFields, field)
	}

	// append required types for hooks to types field, but do not
	// include them as params in constructor call
	for i, t := range ann.Hooks {
		params, _ := t.parameters(results...)
		field := reflect.StructField{
			Name: fmt.Sprintf("Hook%d", i),
			Type: params,
		}
		inFields = append(inFields, field)
	}

	types = []reflect.Type{reflect.StructOf(inFields)}
	remap = func(args []reflect.Value) []reflect.Value {
		params := args[0]
		args = args[:0]
		for i := 0; i < ft.NumIn(); i++ {
			args = append(args, params.Field(i+1))
		}
		return args
	}

	hookValueMap = func(hook int, args []reflect.Value, results []reflect.Value) (out []reflect.Value) {
		params := args[0]
		if params.Kind() == reflect.Struct {
			var zero reflect.Value
			value := params.FieldByName(fmt.Sprintf("Hook%d", hook))

			if value != zero {
				out = append(out, value)
			}
		}
		for _, r := range results {
			if r.Type() != _typeOfError {
				out = append(out, r)
			}
		}
		return
	}
	return
}

// results returns the types of the results of the annotated function,
// and a function that maps the results of the target function,
// into a result compatible with the annotated function.
func (ann *annotated) results() (
	types []reflect.Type,
	remap func([]reflect.Value) []reflect.Value,
	err error,
) {
	ft := reflect.TypeOf(ann.Target)
	types = make([]reflect.Type, ft.NumOut())

	for i := 0; i < ft.NumOut(); i++ {
		types[i] = ft.Out(i)
	}

	// No result annotations. Return the original types
	// and an identity function.
	if len(ann.ResultTags) == 0 && len(ann.As) == 0 {
		return types, func(results []reflect.Value) []reflect.Value {
			return results
		}, nil
	}

	numStructs := 1
	if len(ann.As) > 0 {
		numStructs = len(ann.As)
	}

	type outStructInfo struct {
		Fields  []reflect.StructField // fields of the struct
		Offsets []int                 // Offsets[i] is the index of result i in Fields
	}

	outs := make([]outStructInfo, numStructs)

	for i := 0; i < numStructs; i++ {
		outs[i].Fields = []reflect.StructField{
			{
				Name:      "Out",
				Type:      reflect.TypeOf(Out{}),
				Anonymous: true,
			},
		}
		outs[i].Offsets = make([]int, len(types))
	}

	var hasError bool

	for i, t := range types {
		if t == _typeOfError {
			// Guarantee that:
			// - only the last result is an error
			// - there is at most one error result
			if i != len(types)-1 {
				return nil, nil, fmt.Errorf(
					"only the last result can be an error: "+
						"%v (%v) returns error as result %d",
					fxreflect.FuncName(ann.Target), ft, i)
			}
			hasError = true
			continue
		}

		for j := 0; j < numStructs; j++ {
			field := reflect.StructField{
				Name: fmt.Sprintf("Field%d", i),
				Type: t,
			}

			if len(ann.As) > 0 && i < len(ann.As[j]) {
				if !t.Implements(ann.As[j][i]) {
					return nil, nil, fmt.Errorf("invalid fx.As: %v does not implement %v", t, ann.As[i])
				}
				field.Type = ann.As[j][i]
			}
			if i < len(ann.ResultTags) {
				field.Tag = reflect.StructTag(ann.ResultTags[i])
			}
			outs[j].Offsets[i] = len(outs[j].Fields)
			outs[j].Fields = append(outs[j].Fields, field)
		}
	}

	var resTypes []reflect.Type
	for _, out := range outs {
		resTypes = append(resTypes, reflect.StructOf(out.Fields))
	}

	outTypes := resTypes
	if hasError {
		outTypes = append(resTypes, _typeOfError)
	}

	return outTypes, func(results []reflect.Value) []reflect.Value {
		var (
			outErr     error
			outResults []reflect.Value
		)

		for _, resType := range resTypes {
			outResults = append(outResults, reflect.New(resType).Elem())
		}

		for i, r := range results {
			if i == len(results)-1 && hasError {
				// If hasError and this is the last item,
				// we are guaranteed that this is an error
				// object.
				if err, _ := r.Interface().(error); err != nil {
					outErr = err
				}
				continue
			}
			for j := range resTypes {
				if fieldIdx := outs[j].Offsets[i]; fieldIdx > 0 {
					// fieldIdx 0 is an invalid index
					// because it refers to uninitialized
					// outs and would point to fx.Out in the
					// struct definition. We need to check this
					// to prevent panic from setting fx.Out to
					// a value.
					outResults[j].Field(fieldIdx).Set(r)
				}
			}
		}

		if hasError {
			if outErr != nil {
				outResults = append(outResults, reflect.ValueOf(outErr))
			} else {
				outResults = append(outResults, _nilError)
			}
		}

		return outResults
	}, nil
}

// Annotate lets you annotate a function's parameters and returns
// without you having to declare separate struct definitions for them.
//
// For example,
//
//	func NewGateway(ro, rw *db.Conn) *Gateway { ... }
//	fx.Provide(
//	  fx.Annotate(
//	    NewGateway,
//	    fx.ParamTags(`name:"ro" optional:"true"`, `name:"rw"`),
//	    fx.ResultTags(`name:"foo"`),
//	  ),
//	)
//
// Is equivalent to,
//
//	type params struct {
//	  fx.In
//
//	  RO *db.Conn `name:"ro" optional:"true"`
//	  RW *db.Conn `name:"rw"`
//	}
//
//	type result struct {
//	  fx.Out
//
//	  GW *Gateway `name:"foo"`
//	}
//
//	fx.Provide(func(p params) result {
//	   return result{GW: NewGateway(p.RO, p.RW)}
//	})
//
// Annotate cannot be used on functions that takes in or returns
// [In] or [Out] structs.
//
// Using the same annotation multiple times is invalid.
// For example, the following will fail with an error:
//
//	fx.Provide(
//	  fx.Annotate(
//	    NewGateWay,
//	    fx.ParamTags(`name:"ro" optional:"true"`),
//	    fx.ParamTags(`name:"rw"), // ERROR: ParamTags was already used above
//	    fx.ResultTags(`name:"foo"`)
//	  )
//	)
//
// is considered an invalid usage and will not apply any of the
// Annotations to NewGateway.
//
// If more tags are given than the number of parameters/results, only
// the ones up to the number of parameters/results will be applied.
//
// # Variadic functions
//
// If the provided function is variadic, Annotate treats its parameter as a
// slice. For example,
//
//	fx.Annotate(func(w io.Writer, rs ...io.Reader) {
//	  // ...
//	}, ...)
//
// Is equivalent to,
//
//	fx.Annotate(func(w io.Writer, rs []io.Reader) {
//	  // ...
//	}, ...)
//
// You can use variadic parameters with Fx's value groups.
// For example,
//
//	fx.Annotate(func(mux *http.ServeMux, handlers ...http.Handler) {
//	  // ...
//	}, fx.ParamTags(``, `group:"server"`))
//
// If we provide the above to the application,
// any constructor in the Fx application can inject its HTTP handlers
// by using fx.Annotate, fx.Annotated, or fx.Out.
//
//	fx.Annotate(
//	  func(..) http.Handler { ... },
//	  fx.ResultTags(`group:"server"`),
//	)
//
//	fx.Annotated{
//	  Target: func(..) http.Handler { ... },
//	  Group:  "server",
//	}
func Annotate(t interface{}, anns ...Annotation) interface{} {
	result := annotated{Target: t}
	for _, ann := range anns {
		if err := ann.apply(&result); err != nil {
			return annotationError{
				target: t,
				err:    err,
			}
		}
	}
	return result
}
