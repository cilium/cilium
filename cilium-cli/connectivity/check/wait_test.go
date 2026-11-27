// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	healthmodels "github.com/cilium/cilium/api/v1/health/models"
)

func TestUnreachablePaths(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   []string
	}{
		{
			name: "all reachable",
			status: `{"nodes": [null, {"name": "node-b",
				"host": {"primary-address": {"ip": "192.168.70.177", "icmp": {}, "http": {}}},
				"health-endpoint": {"primary-address": {"ip": "192.168.71.116", "icmp": {}, "http": {}}}}]}`,
		},
		{
			name: "dead endpoint and unprobed paths",
			status: `{"nodes": [{"name": "node-b",
				"host": {
					"primary-address": {"ip": "192.168.70.177", "icmp": {}, "http": {}},
					"secondary-addresses": [{"ip": "192.168.67.70"}]
				},
				"health-endpoint": {"primary-address": {"ip": "192.168.77.121",
					"icmp": {"status": "Connection timed out"},
					"http": {"status": "context deadline exceeded"}}}}]}`,
			want: []string{
				"node-a -> node-b: host 192.168.67.70: no probe result",
				"node-a -> node-b: endpoint 192.168.77.121: icmp Connection timed out, http context deadline exceeded",
			},
		},
		{
			name:   "http only",
			status: `{"nodes": [{"name": "node-b", "host": {"primary-address": {"ip": "192.168.70.177", "icmp": {}, "http": {"status": "connection refused"}}}}]}`,
			want:   []string{"node-a -> node-b: host 192.168.70.177: http connection refused"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var status healthmodels.HealthStatusResponse
			require.NoError(t, json.Unmarshal([]byte(tt.status), &status))
			require.Equal(t, tt.want, unreachablePaths("node-a", &status))
		})
	}
}

func TestWithNodeReachabilityCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	// A nil K8sClient panics if the agents are queried.
	ct := &ConnectivityTest{ciliumPods: map[string]Pod{"kube-system/cilium-a": {}}}
	err := errors.New("lookup timed out")
	require.Equal(t, err, withNodeReachability(ctx, ct, err))
}
