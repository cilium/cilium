// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package alignchecker

import (
	"reflect"
	"strings"
	"testing"
)

func TestAlignChecker(t *testing.T) {
	type foo struct {
		ipv6 [4]uint32 `align:"$union0"`
		misc uint32    `align:"$union1"`
		f    uint8     `align:"family"`
		pad4 uint8     `align:"pad4"`
		pad5 uint16    `align:"pad5"`
	}

	type foo2 struct {
		foo
	}

	type fooInvalidSize struct {
		ipv6 uint32
	}

	type fooInvalidOffset struct {
		ipv6 [4]uint32 `align:"$union0"`
		misc uint32    `align:"$union1"`
		f    uint16    `align:"family"`
		pad4 uint8     `align:"pad4"`
		pad5 uint8     `align:"pad5"`
	}

	type toCheck map[string][]reflect.Type

	testCases := []struct {
		cName   string
		goTypes []reflect.Type
		err     string
	}{
		{
			"foo",
			[]reflect.Type{
				reflect.TypeOf(foo{}),
			},
			"",
		},
		{
			"foo",
			[]reflect.Type{
				reflect.TypeOf(foo2{}),
			},
			"",
		},
		{
			"foo",
			[]reflect.Type{
				reflect.TypeOf(foo{}),
				reflect.TypeOf(foo2{}),
			},
			"",
		},
		{
			"foo",
			[]reflect.Type{
				reflect.TypeOf(fooInvalidSize{}),
			},
			"fooInvalidSize(4) size does not match foo(24)",
		},
		{
			"foo",
			[]reflect.Type{
				reflect.TypeOf(fooInvalidOffset{}),
			},
			"fooInvalidOffset.pad4 offset(22) does not match foo.pad4(21)",
		},
		{
			"bar",
			[]reflect.Type{
				reflect.TypeOf(foo{}),
			},
			"could not find C struct bar",
		},
	}

	for _, tt := range testCases {
		err := CheckStructAlignments("testdata/bpf_foo.o", toCheck{tt.cName: tt.goTypes}, true)
		if tt.err != "" {
			if !strings.Contains(err.Error(), tt.err) {
				t.Fatalf("error '%s' did not contain string '%s'", err, tt.err)
			}
			return
		}

		if err != nil {
			t.Fatalf("unexpected error checking %s: %s", tt.cName, err)
		}
	}
}
