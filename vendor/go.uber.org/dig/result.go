// Copyright (c) 2019 Uber Technologies, Inc.
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
	"errors"
	"fmt"
	"reflect"

	"go.uber.org/dig/internal/dot"
)

// The result interface represents a result produced by a constructor.
//
// The following implementations exist:
//   resultList    All values returned by the constructor.
//   resultSingle  A single value produced by a constructor.
//   resultObject  dig.Out struct where each field in the struct can be
//                 another result.
//   resultGrouped A value produced by a constructor that is part of a value
//                 group.
type result interface {
	// Extracts the values for this result from the provided value and
	// stores them into the provided containerWriter.
	//
	// This MAY panic if the result does not consume a single value.
	Extract(containerWriter, reflect.Value)

	// DotResult returns a slice of dot.Result(s).
	DotResult() []*dot.Result
}

var (
	_ result = resultSingle{}
	_ result = resultObject{}
	_ result = resultList{}
	_ result = resultGrouped{}
)

type resultOptions struct {
	// If set, this is the name of the associated result value.
	//
	// For Result Objects, name:".." tags on fields override this.
	Name  string
	Group string
}

// newResult builds a result from the given type.
func newResult(t reflect.Type, opts resultOptions) (result, error) {
	switch {
	case IsIn(t) || (t.Kind() == reflect.Ptr && IsIn(t.Elem())) || embedsType(t, _inPtrType):
		return nil, errf("cannot provide parameter objects", "%v embeds a dig.In", t)
	case isError(t):
		return nil, errf("cannot return an error here, return it from the constructor instead")
	case IsOut(t):
		return newResultObject(t, opts)
	case embedsType(t, _outPtrType):
		return nil, errf(
			"cannot build a result object by embedding *dig.Out, embed dig.Out instead",
			"%v embeds *dig.Out", t)
	case t.Kind() == reflect.Ptr && IsOut(t.Elem()):
		return nil, errf(
			"cannot return a pointer to a result object, use a value instead",
			"%v is a pointer to a struct that embeds dig.Out", t)
	case len(opts.Group) > 0:
		g, err := parseGroupString(opts.Group)
		if err != nil {
			return nil, errf(
				"cannot parse group %q", opts.Group, err)
		}
		rg := resultGrouped{Type: t, Group: g.Name, Flatten: g.Flatten}
		if g.Flatten {
			if t.Kind() != reflect.Slice {
				return nil, errf(
					"flatten can be applied to slices only",
					"%v is not a slice", t)
			}
			rg.Type = rg.Type.Elem()
		}
		return rg, nil
	default:
		return resultSingle{Type: t, Name: opts.Name}, nil
	}
}

// resultVisitor visits every result in a result tree, allowing tracking state
// at each level.
type resultVisitor interface {
	// Visit is called on the result being visited.
	//
	// If Visit returns a non-nil resultVisitor, that resultVisitor visits all
	// the child results of this result.
	Visit(result) resultVisitor

	// AnnotateWithField is called on each field of a resultObject after
	// visiting it but before walking its descendants.
	//
	// The same resultVisitor is used for all fields: the one returned upon
	// visiting the resultObject.
	//
	// For each visited field, if AnnotateWithField returns a non-nil
	// resultVisitor, it will be used to walk the result of that field.
	AnnotateWithField(resultObjectField) resultVisitor

	// AnnotateWithPosition is called with the index of each result of a
	// resultList after vising it but before walking its descendants.
	//
	// The same resultVisitor is used for all results: the one returned upon
	// visiting the resultList.
	//
	// For each position, if AnnotateWithPosition returns a non-nil
	// resultVisitor, it will be used to walk the result at that index.
	AnnotateWithPosition(idx int) resultVisitor
}

// walkResult walks the result tree for the given result with the provided
// visitor.
//
// resultVisitor.Visit will be called on the provided result and if a non-nil
// resultVisitor is received, it will be used to walk its descendants. If a
// resultObject or resultList was visited, AnnotateWithField and
// AnnotateWithPosition respectively will be called before visiting the
// descendants of that resultObject/resultList.
//
// This is very similar to how go/ast.Walk works.
func walkResult(r result, v resultVisitor) {
	v = v.Visit(r)
	if v == nil {
		return
	}

	switch res := r.(type) {
	case resultSingle, resultGrouped:
		// No sub-results
	case resultObject:
		w := v
		for _, f := range res.Fields {
			if v := w.AnnotateWithField(f); v != nil {
				walkResult(f.Result, v)
			}
		}
	case resultList:
		w := v
		for i, r := range res.Results {
			if v := w.AnnotateWithPosition(i); v != nil {
				walkResult(r, v)
			}
		}
	default:
		panic(fmt.Sprintf(
			"It looks like you have found a bug in dig. "+
				"Please file an issue at https://github.com/uber-go/dig/issues/ "+
				"and provide the following message: "+
				"received unknown result type %T", res))
	}
}

// resultList holds all values returned by the constructor as results.
type resultList struct {
	ctype reflect.Type

	Results []result

	// For each item at index i returned by the constructor, resultIndexes[i]
	// is the index in .Results for the corresponding result object.
	// resultIndexes[i] is -1 for errors returned by constructors.
	resultIndexes []int
}

func (rl resultList) DotResult() []*dot.Result {
	var types []*dot.Result
	for _, result := range rl.Results {
		types = append(types, result.DotResult()...)
	}
	return types
}

func newResultList(ctype reflect.Type, opts resultOptions) (resultList, error) {
	rl := resultList{
		ctype:         ctype,
		Results:       make([]result, 0, ctype.NumOut()),
		resultIndexes: make([]int, ctype.NumOut()),
	}

	resultIdx := 0
	for i := 0; i < ctype.NumOut(); i++ {
		t := ctype.Out(i)
		if isError(t) {
			rl.resultIndexes[i] = -1
			continue
		}

		r, err := newResult(t, opts)
		if err != nil {
			return rl, errf("bad result %d", i+1, err)
		}

		rl.Results = append(rl.Results, r)
		rl.resultIndexes[i] = resultIdx
		resultIdx++
	}

	return rl, nil
}

func (resultList) Extract(containerWriter, reflect.Value) {
	panic("It looks like you have found a bug in dig. " +
		"Please file an issue at https://github.com/uber-go/dig/issues/ " +
		"and provide the following message: " +
		"resultList.Extract() must never be called")
}

func (rl resultList) ExtractList(cw containerWriter, values []reflect.Value) error {
	for i, v := range values {
		if resultIdx := rl.resultIndexes[i]; resultIdx >= 0 {
			rl.Results[resultIdx].Extract(cw, v)
			continue
		}

		if err, _ := v.Interface().(error); err != nil {
			return err
		}
	}

	return nil
}

// resultSingle is an explicit value produced by a constructor, optionally
// with a name.
//
// This object will be added to the graph as-is.
type resultSingle struct {
	Name string
	Type reflect.Type
}

func (rs resultSingle) DotResult() []*dot.Result {
	return []*dot.Result{
		{
			Node: &dot.Node{
				Type: rs.Type,
				Name: rs.Name,
			},
		},
	}
}

func (rs resultSingle) Extract(cw containerWriter, v reflect.Value) {
	cw.setValue(rs.Name, rs.Type, v)
}

// resultObject is a dig.Out struct where each field is another result.
//
// This object is not added to the graph. Its fields are interpreted as
// results and added to the graph if needed.
type resultObject struct {
	Type   reflect.Type
	Fields []resultObjectField
}

func (ro resultObject) DotResult() []*dot.Result {
	var types []*dot.Result
	for _, field := range ro.Fields {
		types = append(types, field.DotResult()...)
	}
	return types
}

func newResultObject(t reflect.Type, opts resultOptions) (resultObject, error) {
	ro := resultObject{Type: t}
	if len(opts.Name) > 0 {
		return ro, errf(
			"cannot specify a name for result objects", "%v embeds dig.Out", t)
	}

	if len(opts.Group) > 0 {
		return ro, errf(
			"cannot specify a group for result objects", "%v embeds dig.Out", t)
	}

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Type == _outType {
			// Skip over the dig.Out embed.
			continue
		}

		rof, err := newResultObjectField(i, f, opts)
		if err != nil {
			return ro, errf("bad field %q of %v", f.Name, t, err)
		}

		ro.Fields = append(ro.Fields, rof)
	}
	return ro, nil
}

func (ro resultObject) Extract(cw containerWriter, v reflect.Value) {
	for _, f := range ro.Fields {
		f.Result.Extract(cw, v.Field(f.FieldIndex))
	}
}

// resultObjectField is a single field inside a dig.Out struct.
type resultObjectField struct {
	// Name of the field in the struct.
	FieldName string

	// Index of the field in the struct.
	//
	// We need to track this separately because not all fields of the struct
	// map to results.
	FieldIndex int

	// Result produced by this field.
	Result result
}

func (rof resultObjectField) DotResult() []*dot.Result {
	return rof.Result.DotResult()
}

// newResultObjectField(i, f, opts) builds a resultObjectField from the field
// f at index i.
func newResultObjectField(idx int, f reflect.StructField, opts resultOptions) (resultObjectField, error) {
	rof := resultObjectField{
		FieldName:  f.Name,
		FieldIndex: idx,
	}

	var r result
	switch {
	case f.PkgPath != "":
		return rof, errf(
			"unexported fields not allowed in dig.Out, did you mean to export %q (%v)?", f.Name, f.Type)

	case f.Tag.Get(_groupTag) != "":
		var err error
		r, err = newResultGrouped(f)
		if err != nil {
			return rof, err
		}

	default:
		var err error
		if name := f.Tag.Get(_nameTag); len(name) > 0 {
			// can modify in-place because options are passed-by-value.
			opts.Name = name
		}
		r, err = newResult(f.Type, opts)
		if err != nil {
			return rof, err
		}
	}

	rof.Result = r
	return rof, nil
}

// resultGrouped is a value produced by a constructor that is part of a result
// group.
//
// These will be produced as fields of a dig.Out struct.
type resultGrouped struct {
	// Name of the group as specified in the `group:".."` tag.
	Group string

	// Type of value produced.
	Type reflect.Type

	// Indicates elements of a value are to be injected individually, instead of
	// as a group. Requires the value's slice to be a group. If set, Type will be
	// the type of individual elements rather than the group.
	Flatten bool
}

func (rt resultGrouped) DotResult() []*dot.Result {
	return []*dot.Result{
		{
			Node: &dot.Node{
				Type:  rt.Type,
				Group: rt.Group,
			},
		},
	}
}

// newResultGrouped(f) builds a new resultGrouped from the provided field.
func newResultGrouped(f reflect.StructField) (resultGrouped, error) {
	g, err := parseGroupString(f.Tag.Get(_groupTag))
	if err != nil {
		return resultGrouped{}, err
	}
	rg := resultGrouped{
		Group:   g.Name,
		Flatten: g.Flatten,
		Type:    f.Type,
	}
	name := f.Tag.Get(_nameTag)
	optional, _ := isFieldOptional(f)
	switch {
	case g.Flatten && f.Type.Kind() != reflect.Slice:
		return rg, errf("flatten can be applied to slices only",
			"field %q (%v) is not a slice", f.Name, f.Type)
	case name != "":
		return rg, errf(
			"cannot use named values with value groups",
			"name:%q provided with group:%q", name, rg.Group)
	case optional:
		return rg, errors.New("value groups cannot be optional")
	}
	if g.Flatten {
		rg.Type = f.Type.Elem()
	}

	return rg, nil
}

func (rt resultGrouped) Extract(cw containerWriter, v reflect.Value) {
	if !rt.Flatten {
		cw.submitGroupedValue(rt.Group, rt.Type, v)
		return
	}
	for i := 0; i < v.Len(); i++ {
		cw.submitGroupedValue(rt.Group, rt.Type, v.Index(i))
	}
}
