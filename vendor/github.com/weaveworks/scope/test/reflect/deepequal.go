// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Deep equality test via reflection

package reflect

import (
	"reflect"
)

// During deepValueEqual, must keep track of checks that are
// in progress.  The comparison algorithm assumes that all
// checks in progress are true when it reencounters them.
// Visited comparisons are stored in a map indexed by visit.
type visit struct {
	a1  uintptr
	a2  uintptr
	typ reflect.Type
}

// Tests for deep equality using reflected types. The map argument tracks
// comparisons that have already been seen, which allows short circuiting on
// recursive types.
func deepValueEqual(v1, v2 reflect.Value, visited map[visit]bool, depth int) bool {
	if !v1.IsValid() || !v2.IsValid() {
		return v1.IsValid() == v2.IsValid()
	}
	if v1.Type() != v2.Type() {
		return false
	}

	// if depth > 10 { panic("deepValueEqual") }	// for debugging

	if v1.CanAddr() && v2.CanAddr() && hard(v1.Kind()) {
		addr1 := v1.UnsafeAddr()
		addr2 := v2.UnsafeAddr()
		if addr1 > addr2 {
			// Canonicalize order to reduce number of entries in visited.
			addr1, addr2 = addr2, addr1
		}

		// Short circuit if references are identical ...
		if addr1 == addr2 {
			return true
		}

		// ... or already seen
		typ := v1.Type()
		v := visit{addr1, addr2, typ}
		if visited[v] {
			return true
		}

		// Remember for later.
		visited[v] = true
	}

	if m := v1.MethodByName("DeepEqual"); m.IsValid() {
		results := m.Call([]reflect.Value{v2})
		if len(results) != 1 || results[0].Kind() != reflect.Bool {
			panic("DeepEqual must return 1 bool")
		}
		return results[0].Bool()
	}

	test, ok := map[reflect.Kind]func(v1, v2 reflect.Value, visited map[visit]bool, depth int) bool{
		reflect.Array:     arrayEq,
		reflect.Slice:     sliceEq,
		reflect.Interface: interfaceEq,
		reflect.Ptr:       pointerEq,
		reflect.Struct:    structEq,
		reflect.Map:       mapEq,
		reflect.Func:      funcEq,
		reflect.Bool:      boolEq,
		reflect.Float32:   floatEq,
		reflect.Float64:   floatEq,
		reflect.Int:       intEq,
		reflect.Int8:      intEq,
		reflect.Int16:     intEq,
		reflect.Int32:     intEq,
		reflect.Int64:     intEq,
		reflect.Uint:      uintEq,
		reflect.Uintptr:   uintEq,
		reflect.Uint8:     uintEq,
		reflect.Uint16:    uintEq,
		reflect.Uint32:    uintEq,
		reflect.Uint64:    uintEq,
		reflect.String:    stringEq,
	}[v1.Kind()]
	if !ok {
		test = normalEq
	}
	return test(v1, v2, visited, depth)
}

func hard(k reflect.Kind) bool {
	switch k {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.Struct:
		return true
	}
	return false
}

func arrayEq(v1, v2 reflect.Value, visited map[visit]bool, depth int) bool {
	for i := 0; i < v1.Len(); i++ {
		if !deepValueEqual(v1.Index(i), v2.Index(i), visited, depth+1) {
			return false
		}
	}
	return true
}

func sliceEq(v1, v2 reflect.Value, visited map[visit]bool, depth int) bool {
	if v1.IsNil() != v2.IsNil() {
		return false
	}
	if v1.Len() != v2.Len() {
		return false
	}
	if v1.Pointer() == v2.Pointer() {
		return true
	}
	for i := 0; i < v1.Len(); i++ {
		if !deepValueEqual(v1.Index(i), v2.Index(i), visited, depth+1) {
			return false
		}
	}
	return true
}

func interfaceEq(v1, v2 reflect.Value, visited map[visit]bool, depth int) bool {
	if v1.IsNil() || v2.IsNil() {
		return v1.IsNil() == v2.IsNil()
	}
	return deepValueEqual(v1.Elem(), v2.Elem(), visited, depth+1)
}

func pointerEq(v1, v2 reflect.Value, visited map[visit]bool, depth int) bool {
	return deepValueEqual(v1.Elem(), v2.Elem(), visited, depth+1)
}

func structEq(v1, v2 reflect.Value, visited map[visit]bool, depth int) bool {
	for i, n := 0, v1.NumField(); i < n; i++ {
		if v1.Type().Field(i).Tag.Get("deepequal") == "skip" {
			continue
		}
		if !deepValueEqual(v1.Field(i), v2.Field(i), visited, depth+1) {
			return false
		}
	}
	return true
}

func mapEq(v1, v2 reflect.Value, visited map[visit]bool, depth int) bool {
	if v1.IsNil() != v2.IsNil() {
		return false
	}
	if v1.Len() != v2.Len() {
		return false
	}
	if v1.Pointer() == v2.Pointer() {
		return true
	}
	for _, k := range v1.MapKeys() {
		if !deepValueEqual(v1.MapIndex(k), v2.MapIndex(k), visited, depth+1) {
			return false
		}
	}
	return true
}

func funcEq(v1, v2 reflect.Value, visited map[visit]bool, depth int) bool {
	if v1.IsNil() && v2.IsNil() {
		return true
	}
	// Can't do better than this:
	return false
}

func boolEq(v1, v2 reflect.Value, _ map[visit]bool, _ int) bool   { return v1.Bool() == v2.Bool() }
func floatEq(v1, v2 reflect.Value, _ map[visit]bool, _ int) bool  { return v1.Float() == v2.Float() }
func intEq(v1, v2 reflect.Value, _ map[visit]bool, _ int) bool    { return v1.Int() == v2.Int() }
func uintEq(v1, v2 reflect.Value, _ map[visit]bool, _ int) bool   { return v1.Uint() == v2.Uint() }
func stringEq(v1, v2 reflect.Value, _ map[visit]bool, _ int) bool { return v1.String() == v2.String() }

func normalEq(v1, v2 reflect.Value, _ map[visit]bool, _ int) bool {
	if v1.CanInterface() && v2.CanInterface() {
		return v1.Interface() == v1.Interface()
	} else if v1.CanInterface() || v2.CanInterface() {
		return false
	}
	return true
}

// DeepEqual tests for deep equality. It uses normal == equality where
// possible but will scan elements of arrays, slices, maps, and fields of
// structs. In maps, keys are compared with == but elements use deep
// equality. DeepEqual correctly handles recursive types. Functions are equal
// only if they are both nil.
// An empty slice is not equal to a nil slice.
func DeepEqual(a1, a2 interface{}) bool {
	if a1 == nil || a2 == nil {
		return a1 == a2
	}
	return deepValueEqual(
		reflect.ValueOf(a1),
		reflect.ValueOf(a2),
		make(map[visit]bool),
		0,
	)
}
