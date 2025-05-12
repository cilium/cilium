// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package analyze

import (
	"fmt"
	"reflect"

	"github.com/cilium/cilium/pkg/container/set"
)

// This code is taken from ebpf-go while we figure out how to export it properly
// from the library.

// Fields extracts object names tagged 'ebpf' from a struct type.
func Fields(to any) (*set.Set[string], error) {
	toValue := reflect.ValueOf(to)
	if toValue.Type().Kind() != reflect.Ptr {
		return nil, fmt.Errorf("%T is not a pointer to struct", to)
	}

	if toValue.IsNil() {
		return nil, fmt.Errorf("nil pointer to %T", to)
	}

	return ebpfFields(toValue.Elem(), nil)
}

// structField represents a struct field containing the ebpf struct tag.
type structField struct {
	reflect.StructField
	value reflect.Value
}

func ebpfFields(structVal reflect.Value, visited map[reflect.Type]bool) (*set.Set[string], error) {
	if visited == nil {
		visited = make(map[reflect.Type]bool)
	}

	structType := structVal.Type()
	if structType.Kind() != reflect.Struct {
		return nil, fmt.Errorf("%s is not a struct", structType)
	}

	if visited[structType] {
		return nil, fmt.Errorf("recursion on type %s", structType)
	}

	keep := set.NewSet[string]()
	for i := 0; i < structType.NumField(); i++ {
		field := structField{structType.Field(i), structVal.Field(i)}

		// If the field is tagged, gather it and move on.
		name := field.Tag.Get("ebpf")
		if name != "" {
			keep.Insert(name)
			continue
		}

		// If the field does not have an ebpf tag, but is a struct or a pointer
		// to a struct, attempt to gather its fields as well.
		var v reflect.Value
		switch field.Type.Kind() {
		case reflect.Ptr:
			if field.Type.Elem().Kind() != reflect.Struct {
				continue
			}

			if field.value.IsNil() {
				return nil, fmt.Errorf("nil pointer to %s", structType)
			}

			// Obtain the destination type of the pointer.
			v = field.value.Elem()

		case reflect.Struct:
			// Reference the value's type directly.
			v = field.value

		default:
			continue
		}

		inner, err := ebpfFields(v, visited)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", field.Name, err)
		}

		keep.Merge(*inner)
	}

	return &keep, nil
}
