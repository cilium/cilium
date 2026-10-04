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
			name:    "missing endpoint",
			config:  &types.RXQueueConfig{},
			wantErr: "exactly one of podEndpoint or serviceEndpoint is required",
		},
		{
			name: "both endpoints",
			config: &types.RXQueueConfig{
				PodEndpoint:     &types.RXQueuePodEndpoint{Port: "9000", Protocol: corev1.ProtocolTCP},
				ServiceEndpoint: &types.RXQueueServiceEndpoint{ServiceName: "storage", Port: "rpc"},
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "unsupported pod protocol",
			config: &types.RXQueueConfig{
				PodEndpoint: &types.RXQueuePodEndpoint{Port: "9000", Protocol: corev1.ProtocolSCTP},
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
			name: "missing service name",
			config: &types.RXQueueConfig{
				ServiceEndpoint: &types.RXQueueServiceEndpoint{Port: "rpc"},
			},
			wantErr: "serviceName is required",
		},
		{
			name: "valid pod endpoint",
			config: &types.RXQueueConfig{
				PodEndpoint: &types.RXQueuePodEndpoint{Port: "rpc", Protocol: corev1.ProtocolTCP},
			},
		},
		{
			name: "valid service endpoint",
			config: &types.RXQueueConfig{
				ServiceEndpoint: &types.RXQueueServiceEndpoint{ServiceName: "storage", Port: "9000"},
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
