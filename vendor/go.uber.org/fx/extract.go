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

package fx

import (
	"fmt"
	"reflect"
	"unicode"
	"unicode/utf8"
)

var _typeOfIn = reflect.TypeOf(In{})

// Extract fills the given struct with values from the dependency injection
// container on application initialization. The target MUST be a pointer to a
// struct. Only exported fields will be filled.
//
// Extract will be deprecated soon: use Populate instead, which doesn't
// require defining a container struct.
func Extract(target interface{}) Option {
	v := reflect.ValueOf(target)

	if t := v.Type(); t.Kind() != reflect.Ptr || t.Elem().Kind() != reflect.Struct {
		return Error(fmt.Errorf("Extract expected a pointer to a struct, got a %v", t))
	}

	v = v.Elem()
	t := v.Type()

	// We generate a function which accepts a single fx.In struct as an
	// argument. This struct contains all exported fields of the target
	// struct.

	// Fields of the generated fx.In struct.
	fields := make([]reflect.StructField, 0, t.NumField()+1)

	// Anonymous dig.In field.
	fields = append(fields, reflect.StructField{
		Name:      _typeOfIn.Name(),
		Anonymous: true,
		Type:      _typeOfIn,
	})

	// List of values in the target struct aligned with the fields of the
	// generated struct.
	//
	// So for example, if the target is,
	//
	// 	var target struct {
	// 		Foo io.Reader
	// 		bar []byte
	// 		Baz io.Writer
	// 	}
	//
	// The generated struct has the shape,
	//
	// 	struct {
	// 		fx.In
	//
	// 		F0 io.Reader
	// 		F2 io.Writer
	// 	}
	//
	// And `targets` is,
	//
	// 	[
	// 		target.Field(0),  // Foo io.Reader
	// 		target.Field(2),  // Baz io.Writer
	// 	]
	//
	// As we iterate through the fields of the generated struct, we can copy
	// the value into the corresponding value in the targets list.
	targets := make([]reflect.Value, 0, t.NumField())

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)

		// Skip unexported fields.
		if f.Anonymous {
			// If embedded, StructField.PkgPath is not a reliable indicator of
			// whether the field is exported. See
			// https://github.com/golang/go/issues/21122

			t := f.Type
			if t.Kind() == reflect.Ptr {
				t = t.Elem()
			}

			if !isExported(t.Name()) {
				continue
			}
		} else if f.PkgPath != "" {
			continue
		}

		// We don't copy over names or embedded semantics.
		fields = append(fields, reflect.StructField{
			Name: fmt.Sprintf("F%d", i),
			Type: f.Type,
			Tag:  f.Tag,
		})
		targets = append(targets, v.Field(i))
	}

	// Equivalent to,
	//
	// 	func(r struct {
	// 		fx.In
	//
	// 		F1 Foo
	// 		F2 Bar
	// 	}) {
	// 		target.Foo = r.F1
	// 		target.Bar = r.F2
	// 	}

	fn := reflect.MakeFunc(
		reflect.FuncOf(
			[]reflect.Type{reflect.StructOf(fields)},
			nil,   /* results */
			false, /* variadic */
		),
		func(args []reflect.Value) []reflect.Value {
			result := args[0]
			for i := 1; i < result.NumField(); i++ {
				targets[i-1].Set(result.Field(i))
			}
			return nil
		},
	)

	return Invoke(fn.Interface())
}

// isExported reports whether the identifier is exported.
func isExported(id string) bool {
	r, _ := utf8.DecodeRuneInString(id)
	return unicode.IsUpper(r)
}
