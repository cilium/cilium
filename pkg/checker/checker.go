// Copyright 2018-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package checker

import (
	"reflect"

	"github.com/cilium/cilium/pkg/comparator"

	"github.com/google/go-cmp/cmp"

	"gopkg.in/check.v1"
)

type diffChecker struct {
	*check.CheckerInfo
}

// DeepEquals is a GoCheck checker that does a diff between two objects and
// pretty-prints any difference between the two. It can act as a substitute
// for DeepEquals.
var (
	defaultParams               = []string{"obtained", "expected"}
	DeepEquals    check.Checker = &diffChecker{
		&check.CheckerInfo{Name: "Diff", Params: defaultParams},
	}
)

// Check performs a diff between two objects provided as parameters, and
// returns either true if the objects are identical, or false otherwise. If
// it returns false, it also returns the unified diff between the expected
// and obtained output.
func (checker *diffChecker) Check(params []interface{}, names []string) (result bool, error string) {
	if len(params) != 2 || len(names) != 2 {
		return false, "params and names must be of length 2"
	}

	if reflect.DeepEqual(params[0], params[1]) {
		return true, ""
	}

	return false, comparator.CompareWithNames(params[0], params[1], names[0], names[1])
}

// DeepEqual tests whether two parameters are deeply equal, and returns true if
// they are. If the objects are not deeply equal, then the second return value
// includes a json representation of the difference between the parameters.
func DeepEqual(params ...interface{}) (bool, string) {
	return DeepEquals.Check(params, defaultParams)
}

type cmpChecker struct {
	*check.CheckerInfo
}

// Equals is a GoCheck checker that does a diff between two objects and
// pretty-prints any difference between the two. It can act as a substitute
// for DeepEquals.
var (
	cmpParams               = []string{"obtained", "expected"}
	Equals    check.Checker = &cmpChecker{
		&check.CheckerInfo{Name: "Equals", Params: cmpParams},
	}
)

// Check performs a diff between two objects provided as parameters, and
// returns either true if the objects are identical, or false otherwise. If
// it returns false, it also returns the unified diff between the expected
// and obtained output.
func (checker *cmpChecker) Check(params []interface{}, _ []string) (result bool, error string) {
	if len(params) < 2 {
		return false, "Parameter missing"
	}

	// Diff expects to receive parameters in order ("expected",
	// "obtained"), but our convention is to pass them as
	// ("obtained", "expected"), so reverse them here.
	diff := cmp.Diff(params[1], params[0], DeepAllowUnexported(params[1], params[0]))

	return diff == "", diff
}

// Equal tests whether two parameters are deeply equal, and returns true if
// they are. If the objects are not deeply equal, then the second return value
// includes a json representation of the difference between the parameters.
func Equal(params ...interface{}) (bool, string) {
	return Equals.Check(params, cmpParams)
}

func DeepAllowUnexported(vs ...interface{}) cmp.Option {
	m := make(map[reflect.Type]struct{})
	for _, v := range vs {
		structTypes(reflect.ValueOf(v), m)
	}
	var typs []interface{}
	for t := range m {
		typs = append(typs, reflect.New(t).Elem().Interface())
	}
	return cmp.AllowUnexported(typs...)
}

func structTypes(v reflect.Value, m map[reflect.Type]struct{}) {
	if !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Ptr:
		if !v.IsNil() {
			structTypes(v.Elem(), m)
		}
	case reflect.Interface:
		if !v.IsNil() {
			structTypes(v.Elem(), m)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			structTypes(v.Index(i), m)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			structTypes(v.MapIndex(k), m)
		}
	case reflect.Struct:
		m[v.Type()] = struct{}{}
		for i := 0; i < v.NumField(); i++ {
			structTypes(v.Field(i), m)
		}
	}
}
