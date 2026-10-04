// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

func TestValidateRXQueueConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *types.RXQueueConfig
		wantErr string
	}{
		{
			name:    "missing config",
			wantErr: "RX queue endpoint is required",
		},
		{
			name:    "missing pod endpoint",
			config:  &types.RXQueueConfig{},
			wantErr: "podEndpoint is required",
		},
		{
			name: "unsupported pod protocol",
			config: &types.RXQueueConfig{
				PodEndpoint: &types.RXQueuePodEndpoint{Port: "9000", Protocol: corev1.ProtocolSCTP},
			},
			wantErr: "protocol must be TCP or UDP",
		},
		{
			name: "missing pod protocol",
			config: &types.RXQueueConfig{
				PodEndpoint: &types.RXQueuePodEndpoint{Port: "9000"},
			},
			wantErr: "protocol must be TCP or UDP",
		},
		{
			name: "invalid pod port",
			config: &types.RXQueueConfig{
				PodEndpoint: &types.RXQueuePodEndpoint{Port: "0", Protocol: corev1.ProtocolTCP},
			},
			wantErr: "between 1 and 65535",
		},
		{
			name: "pod port out of range",
			config: &types.RXQueueConfig{
				PodEndpoint: &types.RXQueuePodEndpoint{Port: "65536", Protocol: corev1.ProtocolTCP},
			},
			wantErr: "between 1 and 65535",
		},
		{
			name: "invalid pod port name",
			config: &types.RXQueueConfig{
				PodEndpoint: &types.RXQueuePodEndpoint{Port: "not_a_port", Protocol: corev1.ProtocolTCP},
			},
			wantErr: "invalid port name",
		},
		{
			name: "missing pod port",
			config: &types.RXQueueConfig{
				PodEndpoint: &types.RXQueuePodEndpoint{Protocol: corev1.ProtocolTCP},
			},
			wantErr: "port is required",
		},
		{
			name: "valid named pod endpoint",
			config: &types.RXQueueConfig{
				PodEndpoint: &types.RXQueuePodEndpoint{Port: "rpc", Protocol: corev1.ProtocolTCP},
			},
		},
		{
			name: "valid numeric pod endpoint",
			config: &types.RXQueueConfig{
				PodEndpoint: &types.RXQueuePodEndpoint{Port: "65535", Protocol: corev1.ProtocolUDP},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRXQueueConfig(tt.config)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
			require.ErrorIs(t, err, errUnexpectedInput)
		})
	}
}

func rxQueueTestPod() *slim_corev1.Pod {
	return &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{Namespace: "default", Name: "storage-0"},
		Spec: slim_corev1.PodSpec{
			Containers: []slim_corev1.Container{{
				Ports: []slim_corev1.ContainerPort{
					{Name: "rpc", ContainerPort: 8080},
					{Name: "dns", ContainerPort: 5353, Protocol: slim_corev1.ProtocolUDP},
				},
			}},
		},
		Status: slim_corev1.PodStatus{
			PodIPs: []slim_corev1.PodIP{{IP: "2001:db8::10"}, {IP: "192.0.2.10"}, {IP: "192.0.2.10"}},
		},
	}
}

func TestResolveRXQueuePodEndpoint(t *testing.T) {
	for _, tt := range []struct {
		name     string
		port     string
		protocol corev1.Protocol
		wantPort uint16
	}{
		{"numeric TCP", "9000", corev1.ProtocolTCP, 9000},
		{"numeric UDP", "9000", corev1.ProtocolUDP, 9000},
		{"named TCP", "rpc", corev1.ProtocolTCP, 8080},
		{"named UDP", "dns", corev1.ProtocolUDP, 5353},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pod := rxQueueTestPod()
			flows, err := resolveRXQueueFlows(pod, &types.RXQueueConfig{
				PodEndpoint: &types.RXQueuePodEndpoint{Port: tt.port, Protocol: tt.protocol},
			}, []netip.Addr{
				netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("::ffff:192.0.2.10"),
			})
			require.NoError(t, err)
			require.Equal(t, []types.RXQueueFlow{
				{DestinationIP: netip.MustParseAddr("192.0.2.10"), DestinationPort: tt.wantPort, Protocol: tt.protocol},
				{DestinationIP: netip.MustParseAddr("2001:db8::10"), DestinationPort: tt.wantPort, Protocol: tt.protocol},
			}, flows)
		})
	}
}

func TestResolveRXQueuePodEndpointInitContainer(t *testing.T) {
	pod := rxQueueTestPod()
	pod.Spec.InitContainers = pod.Spec.Containers
	pod.Spec.Containers = nil
	flows, err := resolveRXQueueFlows(pod, &types.RXQueueConfig{
		PodEndpoint: &types.RXQueuePodEndpoint{Port: "rpc", Protocol: corev1.ProtocolTCP},
	}, []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")})
	require.NoError(t, err)
	require.Len(t, flows, 2)
	require.Equal(t, uint16(8080), flows[0].DestinationPort)
}

func TestResolveRXQueuePodEndpointErrors(t *testing.T) {
	for _, tt := range []struct {
		name    string
		change  func(*slim_corev1.Pod)
		wantErr string
	}{
		{
			name:    "port protocol mismatch",
			change:  func(pod *slim_corev1.Pod) { pod.Spec.Containers[0].Ports[0].Protocol = slim_corev1.ProtocolUDP },
			wantErr: "no TCP port named",
		},
		{
			name:    "missing named port",
			change:  func(pod *slim_corev1.Pod) { pod.Spec.Containers = nil },
			wantErr: "no TCP port named",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pod := rxQueueTestPod()
			tt.change(pod)
			flows, err := resolveRXQueueFlows(pod, &types.RXQueueConfig{
				PodEndpoint: &types.RXQueuePodEndpoint{Port: "rpc", Protocol: corev1.ProtocolTCP},
			}, []netip.Addr{netip.MustParseAddr("192.0.2.10")})
			require.ErrorContains(t, err, tt.wantErr)
			require.Empty(t, flows)
		})
	}
}

func TestResolveRXQueueFlowsUsesCNIAttachmentAddresses(t *testing.T) {
	pod := rxQueueTestPod()
	config := &types.RXQueueConfig{PodEndpoint: &types.RXQueuePodEndpoint{Port: "rpc", Protocol: corev1.ProtocolTCP}}
	address := netip.MustParseAddr("192.0.2.20")
	flows, err := resolveRXQueueFlows(pod, config, []netip.Addr{address})
	require.NoError(t, err)
	require.Equal(t, []types.RXQueueFlow{{DestinationIP: address, DestinationPort: 8080, Protocol: corev1.ProtocolTCP}}, flows,
		"stale API PodIPs must not authorize steering")
	for _, addresses := range [][]netip.Addr{nil, {{}}} {
		flows, err = resolveRXQueueFlows(pod, config, addresses)
		require.Error(t, err)
		require.Nil(t, flows, "missing CNI addresses must not fall back to PodIPs")
	}
}

func TestResolveRXQueueFlowsRequiresPodEndpoint(t *testing.T) {
	for _, config := range []*types.RXQueueConfig{nil, {}} {
		flows, err := resolveRXQueueFlows(rxQueueTestPod(), config, nil)
		require.ErrorIs(t, err, errUnexpectedInput)
		require.Empty(t, flows)
	}
}
