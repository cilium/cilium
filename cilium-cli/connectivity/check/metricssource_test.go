// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/cilium-cli/defaults"
)

func TestConnectivityTestCiliumAgentMetrics(t *testing.T) {
	ciliumPod := Pod{
		Pod: &corev1.Pod{
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: defaults.AgentContainerName,
						Ports: []corev1.ContainerPort{
							{
								Name:          prometheusContainerPortName,
								HostPort:      9962,
								ContainerPort: 9962,
								Protocol:      corev1.ProtocolTCP,
							}},
					},
				},
			},
		},
	}

	podWithPrometheusMissing := Pod{
		Pod: &corev1.Pod{
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: defaults.AgentContainerName,
						Ports: []corev1.ContainerPort{
							{
								Name:          "peer-service",
								HostPort:      4244,
								ContainerPort: 4244,
								Protocol:      corev1.ProtocolTCP,
							}},
					},
				},
			},
		},
	}

	tests := map[string]struct {
		ct   ConnectivityTest
		want MetricsSource
	}{
		"nominal case": {
			ct: ConnectivityTest{ciliumPods: map[string]Pod{
				defaults.AgentContainerName: ciliumPod,
			}},
			want: MetricsSource{
				Name: defaults.AgentContainerName,
				Pods: []Pod{ciliumPod},
				Port: "9962",
			},
		},
		"no cilium pods": {
			ct:   ConnectivityTest{ciliumPods: map[string]Pod{}},
			want: MetricsSource{},
		},
		"no prometheus container port": {
			ct:   ConnectivityTest{ciliumPods: map[string]Pod{defaults.AgentContainerName: podWithPrometheusMissing}},
			want: MetricsSource{},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := tc.ct.CiliumAgentMetrics()
			assert.Equal(t, tc.want, got)
		})
	}
}
