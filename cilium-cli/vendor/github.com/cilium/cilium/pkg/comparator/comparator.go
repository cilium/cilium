// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package comparator

import (
	"github.com/kr/pretty"
	"github.com/pmezard/go-difflib/difflib"
)

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
	return len(m1)-ignoredM1 == len(m2)-ignoredM2
}
