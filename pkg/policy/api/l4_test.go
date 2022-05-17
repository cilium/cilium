// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"testing"
)

func benchmarkIsEmptySetup(count int) []L7Rules {
	rules := make([]L7Rules, 0, count)
	for i := 0; i < count; i++ {
		rules = append(rules, L7Rules{})
	}
	return rules
}

func BenchmarkL7RulesEmpty10000(b *testing.B) {
	rules := benchmarkIsEmptySetup(10000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for i := range rules {
			_ = rules[i].IsEmpty()
		}
	}
}
