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
		_ [4]uint32 `align:"$union0"`
		_ uint32    `align:"$union1"`
		_ uint8     `align:"family"`
		_ uint8     `align:"pad4"`
		_ uint16    `align:"pad5"`
	}

	type foo2 struct {
		_ foo
	}

	type foo3 struct {
		_ [4]uint32 `align:"$union0.ip6"`
		_ uint32    `align:"$union1.p2"`
		_ uint8     `align:"family"`
		_ uint8     `align:"pad4"`
		_ uint16    `align:"pad5"`
	}

	type foo4 struct {
		_ uint32 `align:"$union0.$struct0.ip4"`
		_ uint32 `align:"$union0.$struct0.pad1"`
		_ uint32 `align:"$union0.$struct0.pad2"`
		_ uint32 `align:"$union0.$struct0.pad3"`
		_ uint32 `align:"$union1.p1"`
		_ uint8  `align:"family"`
		_ uint8  `align:"pad4"`
		_ uint16 `align:"pad5"`
	}

	type fooInvalidSize struct {
		_ uint32
	}

	type fooInvalidOffset struct {
		_ [4]uint32 `align:"$union0"`
		_ uint32    `align:"$union1"`
		_ uint16    `align:"family"`
		_ uint8     `align:"pad4"`
		_ uint8     `align:"pad5"`
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
				reflect.TypeOf(foo3{}),
			},
			"",
		},
		{
			"foo",
			[]reflect.Type{
				reflect.TypeOf(foo4{}),
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
