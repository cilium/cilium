// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"testing"
)

func BenchmarkDecisionMarshalJSON(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		for _, d := range []Decision{
			Undecided,
			Allowed,
			Denied,
		} {
			_, _ = d.MarshalJSON()
		}
	}
}
