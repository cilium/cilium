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
	"container/list"
	"fmt"
	"reflect"
	"strconv"
)

var (
	_noValue    reflect.Value
	_errType    = reflect.TypeOf((*error)(nil)).Elem()
	_inPtrType  = reflect.TypeOf((*In)(nil))
	_inType     = reflect.TypeOf(In{})
	_outPtrType = reflect.TypeOf((*Out)(nil))
	_outType    = reflect.TypeOf(Out{})
)

// Placeholder type placed in dig.In/dig.out to make their special nature
// obvious in godocs.
// Otherwise they will appear as plain empty structs.
type digSentinel struct{}

// In may be embedded into structs to request dig to treat them as special
// parameter structs. When a constructor accepts such a struct, instead of the
// struct becoming a dependency for that constructor, all its fields become
// dependencies instead. See the section on Parameter Objects in the
// package-level documentation for more information.
//
// Fields of the struct may optionally be tagged to customize the behavior of
// dig. The following tags are supported,
//
//	name        Requests a value with the same name and type from the
//	            container. See Named Values for more information.
//	optional    If set to true, indicates that the dependency is optional and
//	            the constructor gracefully handles its absence.
//	group       Name of the Value Group from which this field will be filled.
//	            The field must be a slice type. See Value Groups in the
//	            package documentation for more information.
type In struct{ _ digSentinel }

// Out is an embeddable type that signals to dig that the returned
// struct should be treated differently. Instead of the struct itself
// becoming part of the container, all members of the struct will.

// Out may be embedded into structs to request dig to treat them as special
// result structs. When a constructor returns such a struct, instead of the
// struct becoming a result of the constructor, all its fields become results
// of the constructor. See the section on Result Objects in the package-level
// documentation for more information.
//
// Fields of the struct may optionally be tagged to customize the behavior of
// dig. The following tags are supported,
//
//	name        Specifies the name of the value. Only a field on a dig.In
//	            struct with the same 'name' annotation can receive this
//	            value. See Named Values for more information.
//	group       Name of the Value Group to which this field's value is being
//	            sent. See Value Groups in the package documentation for more
//	            information.
type Out struct{ _ digSentinel }

func isError(t reflect.Type) bool {
	return t.Implements(_errType)
}

// IsIn checks whether the given struct is a dig.In struct. A struct qualifies
// as a dig.In struct if it embeds the dig.In type or if any struct that it
// embeds is a dig.In struct. The parameter may be the reflect.Type of the
// struct rather than the struct itself.
//
// A struct MUST qualify as a dig.In struct for its fields to be treated
// specially by dig.
//
// See the documentation for dig.In for a comprehensive list of supported
// tags.
func IsIn(o interface{}) bool {
	return embedsType(o, _inType)
}

// IsOut checks whether the given struct is a dig.Out struct. A struct
// qualifies as a dig.Out struct if it embeds the dig.Out type or if any
// struct that it embeds is a dig.Out struct. The parameter may be the
// reflect.Type of the struct rather than the struct itself.
//
// A struct MUST qualify as a dig.Out struct for its fields to be treated
// specially by dig.
//
// See the documentation for dig.Out for a comprehensive list of supported
// tags.
func IsOut(o interface{}) bool {
	return embedsType(o, _outType)
}

// Returns true if t embeds e or if any of the types embedded by t embed e.
func embedsType(i interface{}, e reflect.Type) bool {
	// TODO: this function doesn't consider e being a pointer.
	// given `type A foo { *In }`, this function would return false for
	// embedding dig.In, which makes for some extra error checking in places
	// that call this function. Might be worthwhile to consider reflect.Indirect
	// usage to clean up the callers.

	if i == nil {
		return false
	}

	// maybe it's already a reflect.Type
	t, ok := i.(reflect.Type)
	if !ok {
		// take the type if it's not
		t = reflect.TypeOf(i)
	}

	// We are going to do a breadth-first search of all embedded fields.
	types := list.New()
	types.PushBack(t)
	for types.Len() > 0 {
		t := types.Remove(types.Front()).(reflect.Type)

		if t == e {
			return true
		}

		if t.Kind() != reflect.Struct {
			continue
		}

		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.Anonymous {
				types.PushBack(f.Type)
			}
		}
	}

	// If perf is an issue, we can cache known In objects and Out objects in a
	// map[reflect.Type]struct{}.
	return false
}

// Checks if a field of an In struct is optional.
func isFieldOptional(f reflect.StructField) (bool, error) {
	tag := f.Tag.Get(_optionalTag)
	if tag == "" {
		return false, nil
	}

	optional, err := strconv.ParseBool(tag)
	if err != nil {
		err = newErrInvalidInput(
			fmt.Sprintf("invalid value %q for %q tag on field %v", tag, _optionalTag, f.Name), err)
	}

	return optional, err
}
