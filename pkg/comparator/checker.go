// Copyright 2017-2018 Authors of Cilium
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

package comparator

import (
	"reflect"

	"github.com/kr/pretty"
	"github.com/pmezard/go-difflib/difflib"
	"gopkg.in/check.v1"
)

type diffChecker struct {
	*check.CheckerInfo
}

// DeepEquals is a GoCheck checker that does a diff between two objects and
// pretty-prints any difference between the two. It can act as a substitute
// for DeepEquals.
var DeepEquals check.Checker = &diffChecker{
	&check.CheckerInfo{Name: "Diff", Params: []string{"obtained", "expected"}},
}

// Check performs a diff between two objects provided as parameters, and
// returns either true if the objects are identical, or false otherwise. If
// it returns false, it also returns the unified diff between the expected
// and obtained output.
func (checker *diffChecker) Check(params []interface{}, names []string) (result bool, error string) {
	if reflect.DeepEqual(params[0], params[1]) {
		return true, ""
	}

	return false, compare(params[0], params[1], names[1], names[0])
}

// Compare compares two interfaces and emits a unified diff as string
func Compare(a, b interface{}) string {
	return compare(a, b, "b", "a")
}

func compare(a, b interface{}, nameA, nameB string) string {
	string0 := pretty.Sprintf("%# v", a)
	string1 := pretty.Sprintf("%# v", b)
	diff := difflib.UnifiedDiff{
		A:        difflib.SplitLines(string1),
		B:        difflib.SplitLines(string0),
		FromFile: nameA,
		ToFile:   nameB,
		Context:  32,
	}

	out, err := difflib.GetUnifiedDiffString(diff)
	if err != nil {
		return err.Error()
	}
	return "Unified diff:\n" + out
}

// MapStringEquals returns true if both maps are equal.
func MapStringEquals(m1, m2 map[string]string) bool {
	switch {
	case m1 == nil && m2 == nil:
		return true
	case m1 == nil && m2 != nil,
		m1 != nil && m2 == nil,
		len(m1) != len(m2):
		return false
	}
	for k1, v1 := range m1 {
		if v2, ok := m2[k1]; !ok || v2 != v1 {
			return false
		}
	}
	return true
}
