// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package comparator

import "slices"

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
		if slices.Contains(ignoreKeys, k1) {
			ignore = true
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
