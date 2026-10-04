// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

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
