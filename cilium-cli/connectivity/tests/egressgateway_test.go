// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
)

func TestEgressGatewayPolicyEntriesForPodWithIPv6Primary(t *testing.T) {
	pod := check.Pod{Pod: &corev1.Pod{
		Status: corev1.PodStatus{
			PodIP: "fd00:10:244::a88c",
			PodIPs: []corev1.PodIP{
				{IP: "fd00:10:244::a88c"},
				{IP: "10.244.2.42"},
			},
		},
	}}

	want := []check.BPFEgressGatewayPolicyEntry{
		{
			SourceIP:  "10.244.2.42",
			DestCIDR:  "0.0.0.0/0",
			EgressIP:  "172.20.0.3",
			GatewayIP: "172.20.0.3",
		},
		{
			SourceIP:  "fd00:10:244::a88c",
			DestCIDR:  "::/0",
			EgressIP:  "fc00:c111::3",
			GatewayIP: "172.20.0.3",
		},
	}

	got := egressGatewayPolicyEntriesForPod(pod, true, "172.20.0.3", "fc00:c111::3", "172.20.0.3")
	assert.Equal(t, want, got)
}
