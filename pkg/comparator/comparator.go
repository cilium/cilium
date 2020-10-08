// Copyright 2017-2020 Authors of Cilium
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
	"github.com/kr/pretty"
	"github.com/pmezard/go-difflib/difflib"
)

// Compare compares two interfaces and emits a unified diff as string
func Compare(a, b interface{}) string {
	return CompareWithNames(a, b, "a", "b")
}

// CompareWithNames compares two interfaces and emits a unified diff as string
func CompareWithNames(a, b interface{}, nameA, nameB string) string {
	stringA := pretty.Sprintf("%# v", a)
	stringB := pretty.Sprintf("%# v", b)
	diff := difflib.UnifiedDiff{
		A:        difflib.SplitLines(stringA),
		B:        difflib.SplitLines(stringB),
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

// MapBoolEquals returns true if both maps are equal.
func MapBoolEquals(m1, m2 map[string]bool) bool {
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

// MapStringEqualsIgnoreKeys returns true if both maps have the same values for
// the keys that are not present in the 'ignoreKeys'.
func MapStringEqualsIgnoreKeys(m1, m2 map[string]string, ignoreKeys []string) bool {
	switch {
	case m1 == nil && m2 == nil:
		return true
	case m1 == nil && m2 != nil,
		m1 != nil && m2 == nil:
		return false
	}
	ignoredM1 := 0
	for k1, v1 := range m1 {
		var ignore bool
		for _, ig := range ignoreKeys {
			if k1 == ig {
				ignore = true
				break
			}
		}
		if ignore {
			ignoredM1++
			continue
		}
		if v2, ok := m2[k1]; !ok || v2 != v1 {
			return false
		}
	}

	ignoredM2 := 0
	for _, ig := range ignoreKeys {
		if _, ok := m2[ig]; ok {
			ignoredM2++
		}
	}
	if len(m1)-ignoredM1 != len(m2)-ignoredM2 {
		return false
	}
	return true
}
