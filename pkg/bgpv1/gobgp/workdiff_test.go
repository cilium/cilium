// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
//go:build !privileged_tests

package gobgp

import (
	"testing"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func BenchmarkReconcileDiffString(b *testing.B) {
	r := &reconcileDiff{
		seen:      make(map[int]*v2alpha1api.CiliumBGPVirtualRouter),
		state:     &agent.ControlPlaneState{},
		register:  []int{1, 2, 3},
		withdraw:  []int{4, 5, 6, 7, 8},
		reconcile: []int{11, 12, 13, 14, 15, 16},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.String()
	}
}
