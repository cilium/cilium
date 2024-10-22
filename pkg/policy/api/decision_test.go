// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"testing"
)

func BenchmarkDecisionMarshalJSON(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, d := range []Decision{
			Undecided,
			Allowed,
			Denied,
		} {
			_, _ = d.MarshalJSON()
		}
	}
}
