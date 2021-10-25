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

// The param interface represents a dependency for a constructor.
//
// The following implementations exist:
//  paramList     All arguments of the constructor.
//  paramSingle   An explicitly requested type.
//  paramObject   dig.In struct where each field in the struct can be another
//                param.
//  paramGroupedSlice
//                A slice consuming a value group. This will receive all
//                values produced with a `group:".."` tag with the same name
//                as a slice.
type param interface {
	fmt.Stringer

	// Builds this dependency and any of its dependencies from the provided
	// Container.
	//
	// This MAY panic if the param does not produce a single value.
	Build(containerStore) (reflect.Value, error)

	// DotParam returns a slice of dot.Param(s).
	DotParam() []*dot.Param
}

var (
	_ param = paramSingle{}
	_ param = paramObject{}
	_ param = paramList{}
	_ param = paramGroupedSlice{}
)

// newParam builds a param from the given type. If the provided type is a
// dig.In struct, an paramObject will be returned.
func newParam(t reflect.Type) (param, error) {
	switch {
	case IsOut(t) || (t.Kind() == reflect.Ptr && IsOut(t.Elem())) || embedsType(t, _outPtrType):
		return nil, errf("cannot depend on result objects", "%v embeds a dig.Out", t)
	case IsIn(t):
		return newParamObject(t)
	case embedsType(t, _inPtrType):
		return nil, errf(
			"cannot build a parameter object by embedding *dig.In, embed dig.In instead",
			"%v embeds *dig.In", t)
	case t.Kind() == reflect.Ptr && IsIn(t.Elem()):
		return nil, errf(
			"cannot depend on a pointer to a parameter object, use a value instead",
			"%v is a pointer to a struct that embeds dig.In", t)
	default:
		return paramSingle{Type: t}, nil
	}
}

// paramVisitor visits every param in a param tree, allowing tracking state at
// each level.
type paramVisitor interface {
	// Visit is called on the param being visited.
	//
	// If Visit returns a non-nil paramVisitor, that paramVisitor visits all
	// the child params of this param.
	Visit(param) paramVisitor

	// We can implement AnnotateWithField and AnnotateWithPosition like
	// resultVisitor if we need to track that information in the future.
}

// paramVisitorFunc is a paramVisitor that visits param in a tree with the
// return value deciding whether the descendants of this param should be
// recursed into.
type paramVisitorFunc func(param) (recurse bool)

func (f paramVisitorFunc) Visit(p param) paramVisitor {
	if f(p) {
		return f
	}
	return nil
}

// walkParam walks the param tree for the given param with the provided
// visitor.
//
// paramVisitor.Visit will be called on the provided param and if a non-nil
// paramVisitor is received, this param's descendants will be walked with that
// visitor.
//
// This is very similar to how go/ast.Walk works.
func walkParam(p param, v paramVisitor) {
	v = v.Visit(p)
	if v == nil {
		return
	}

	switch par := p.(type) {
	case paramSingle, paramGroupedSlice:
		// No sub-results
	case paramObject:
		for _, f := range par.Fields {
			walkParam(f.Param, v)
		}
	case paramList:
		for _, p := range par.Params {
			walkParam(p, v)
		}
	default:
		panic(fmt.Sprintf(
			"It looks like you have found a bug in dig. "+
				"Please file an issue at https://github.com/uber-go/dig/issues/ "+
				"and provide the following message: "+
				"received unknown param type %T", p))
	}
}

// paramList holds all arguments of the constructor as params.
//
// NOTE: Build() MUST NOT be called on paramList. Instead, BuildList
// must be called.
type paramList struct {
	ctype reflect.Type // type of the constructor

	Params []param
}

func (pl paramList) DotParam() []*dot.Param {
	var types []*dot.Param
	for _, param := range pl.Params {
		types = append(types, param.DotParam()...)
	}
	return types
}

// newParamList builds a paramList from the provided constructor type.
//
// Variadic arguments of a constructor are ignored and not included as
// dependencies.
func newParamList(ctype reflect.Type) (paramList, error) {
	numArgs := ctype.NumIn()
	if ctype.IsVariadic() {
		// NOTE: If the function is variadic, we skip the last argument
		// because we're not filling variadic arguments yet. See #120.
		numArgs--
	}

	pl := paramList{
		ctype:  ctype,
		Params: make([]param, 0, numArgs),
	}

	for i := 0; i < numArgs; i++ {
		p, err := newParam(ctype.In(i))
		if err != nil {
			return pl, errf("bad argument %d", i+1, err)
		}
		pl.Params = append(pl.Params, p)
	}

	return pl, nil
}

func (pl paramList) Build(containerStore) (reflect.Value, error) {
	panic("It looks like you have found a bug in dig. " +
		"Please file an issue at https://github.com/uber-go/dig/issues/ " +
		"and provide the following message: " +
		"paramList.Build() must never be called")
}

// BuildList returns an ordered list of values which may be passed directly
// to the underlying constructor.
func (pl paramList) BuildList(c containerStore) ([]reflect.Value, error) {
	args := make([]reflect.Value, len(pl.Params))
	for i, p := range pl.Params {
		var err error
		args[i], err = p.Build(c)
		if err != nil {
			return nil, err
		}
	}
	return args, nil
}

// paramSingle is an explicitly requested type, optionally with a name.
//
// This object must be present in the graph as-is unless it's specified as
// optional.
type paramSingle struct {
	Name     string
	Optional bool
	Type     reflect.Type
}

func (ps paramSingle) DotParam() []*dot.Param {
	return []*dot.Param{
		{
			Node: &dot.Node{
				Type: ps.Type,
				Name: ps.Name,
			},
			Optional: ps.Optional,
		},
	}
}

func (ps paramSingle) Build(c containerStore) (reflect.Value, error) {
	if v, ok := c.getValue(ps.Name, ps.Type); ok {
		return v, nil
	}

	providers := c.getValueProviders(ps.Name, ps.Type)
	if len(providers) == 0 {
		if ps.Optional {
			return reflect.Zero(ps.Type), nil
		}
		return _noValue, newErrMissingTypes(c, key{name: ps.Name, t: ps.Type})
	}

	for _, n := range providers {
		err := n.Call(c)
		if err == nil {
			continue
		}

		// If we're missing dependencies but the parameter itself is optional,
		// we can just move on.
		if _, ok := err.(errMissingDependencies); ok && ps.Optional {
			return reflect.Zero(ps.Type), nil
		}

		return _noValue, errParamSingleFailed{
			CtorID: n.ID(),
			Key:    key{t: ps.Type, name: ps.Name},
			Reason: err,
		}
	}

	// If we get here, it's impossible for the value to be absent from the
	// container.
	v, _ := c.getValue(ps.Name, ps.Type)
	return v, nil
}

// paramObject is a dig.In struct where each field is another param.
//
// This object is not expected in the graph as-is.
type paramObject struct {
	Type   reflect.Type
	Fields []paramObjectField
}

func (po paramObject) DotParam() []*dot.Param {
	var types []*dot.Param
	for _, field := range po.Fields {
		types = append(types, field.DotParam()...)
	}
	return types
}

// newParamObject builds an paramObject from the provided type. The type MUST
// be a dig.In struct.
func newParamObject(t reflect.Type) (paramObject, error) {
	po := paramObject{Type: t}

	// Check if the In type supports ignoring unexported fields.
	var ignoreUnexported bool
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Type == _inType {
			var err error
			ignoreUnexported, err = isIgnoreUnexportedSet(f)
			if err != nil {
				return po, err
			}
			break
		}
	}

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Type == _inType {
			// Skip over the dig.In embed.
			continue
		}
		if f.PkgPath != "" && ignoreUnexported {
			// Skip over an unexported field if it is allowed.
			continue
		}
		pof, err := newParamObjectField(i, f)
		if err != nil {
			return po, errf("bad field %q of %v", f.Name, t, err)
		}

		po.Fields = append(po.Fields, pof)
	}

	return po, nil
}

func (po paramObject) Build(c containerStore) (reflect.Value, error) {
	dest := reflect.New(po.Type).Elem()
	for _, f := range po.Fields {
		v, err := f.Build(c)
		if err != nil {
			return dest, err
		}
		dest.Field(f.FieldIndex).Set(v)
	}
	return dest, nil
}

// paramObjectField is a single field of a dig.In struct.
type paramObjectField struct {
	// Name of the field in the struct.
	FieldName string

	// Index of this field in the target struct.
	//
	// We need to track this separately because not all fields of the
	// struct map to params.
	FieldIndex int

	// The dependency requested by this field.
	Param param
}

func (pof paramObjectField) DotParam() []*dot.Param {
	return pof.Param.DotParam()
}

func newParamObjectField(idx int, f reflect.StructField) (paramObjectField, error) {
	pof := paramObjectField{
		FieldName:  f.Name,
		FieldIndex: idx,
	}

	var p param
	switch {
	case f.PkgPath != "":
		return pof, errf(
			"unexported fields not allowed in dig.In, did you mean to export %q (%v)?",
			f.Name, f.Type)

	case f.Tag.Get(_groupTag) != "":
		var err error
		p, err = newParamGroupedSlice(f)
		if err != nil {
			return pof, err
		}

	default:
		var err error
		p, err = newParam(f.Type)
		if err != nil {
			return pof, err
		}
	}

	if ps, ok := p.(paramSingle); ok {
		ps.Name = f.Tag.Get(_nameTag)

		var err error
		ps.Optional, err = isFieldOptional(f)
		if err != nil {
			return pof, err
		}

		p = ps
	}

	pof.Param = p
	return pof, nil
}

func (pof paramObjectField) Build(c containerStore) (reflect.Value, error) {
	v, err := pof.Param.Build(c)
	if err != nil {
		return v, err
	}
	return v, nil
}

// paramGroupedSlice is a param which produces a slice of values with the same
// group name.
type paramGroupedSlice struct {
	// Name of the group as specified in the `group:".."` tag.
	Group string

	// Type of the slice.
	Type reflect.Type
}

func (pt paramGroupedSlice) DotParam() []*dot.Param {
	return []*dot.Param{
		{
			Node: &dot.Node{
				Type:  pt.Type,
				Group: pt.Group,
			},
		},
	}
}

// newParamGroupedSlice builds a paramGroupedSlice from the provided type with
// the given name.
//
// The type MUST be a slice type.
func newParamGroupedSlice(f reflect.StructField) (paramGroupedSlice, error) {
	g, err := parseGroupString(f.Tag.Get(_groupTag))
	if err != nil {
		return paramGroupedSlice{}, err
	}
	pg := paramGroupedSlice{Group: g.Name, Type: f.Type}

	name := f.Tag.Get(_nameTag)
	optional, _ := isFieldOptional(f)
	switch {
	case f.Type.Kind() != reflect.Slice:
		return pg, errf("value groups may be consumed as slices only",
			"field %q (%v) is not a slice", f.Name, f.Type)
	case g.Flatten:
		return pg, errf("cannot use flatten in parameter value groups",
			"field %q (%v) specifies flatten", f.Name, f.Type)
	case name != "":
		return pg, errf(
			"cannot use named values with value groups",
			"name:%q requested with group:%q", name, pg.Group)

	case optional:
		return pg, errors.New("value groups cannot be optional")
	}

	return pg, nil
}

func (pt paramGroupedSlice) Build(c containerStore) (reflect.Value, error) {
	for _, n := range c.getGroupProviders(pt.Group, pt.Type.Elem()) {
		if err := n.Call(c); err != nil {
			return _noValue, errParamGroupFailed{
				CtorID: n.ID(),
				Key:    key{group: pt.Group, t: pt.Type.Elem()},
				Reason: err,
			}
		}
	}

	items := c.getValueGroup(pt.Group, pt.Type.Elem())

	result := reflect.MakeSlice(pt.Type, len(items), len(items))
	for i, v := range items {
		result.Index(i).Set(v)
	}
	return result, nil
}
