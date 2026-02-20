// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package tcp

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/ir"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

func TestTcpHandler_Init(t *testing.T) {
	registry := prometheus.NewRegistry()
	opts := &api.MetricConfig{
		ContextOptionConfigs: []*api.ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"namespace"},
			},
			{
				Name:   "destinationContext",
				Values: []string{"namespace"},
			},
		},
	}

	tcpHandler := &tcpHandler{}

	t.Run("Init", func(t *testing.T) {
		require.NoError(t, tcpHandler.Init(registry, opts))
	})

	t.Run("Status", func(t *testing.T) {
		require.Equal(t, "destination=namespace,source=namespace", tcpHandler.Status())
	})
}

func TestTcpHandler(t *testing.T) {

	var supportedFlags = []struct {
		name          string
		flags         ir.TCPFlags
		expectedLabel string
	}{
		{"SYN", ir.TCPFlags{SYN: true}, "SYN"},
		{"SYN_ACK", ir.TCPFlags{SYN: true, ACK: true}, "SYN-ACK"},
		{"FIN", ir.TCPFlags{FIN: true}, "FIN"},
		{"FIN_ACK", ir.TCPFlags{FIN: true, ACK: true}, "FIN"},
		{"RST", ir.TCPFlags{RST: true}, "RST"},
	}

	for _, tc := range supportedFlags {
		registry := prometheus.NewRegistry()
		opts := &api.MetricConfig{
			ContextOptionConfigs: []*api.ContextOptionConfig{
				{
					Name:   "sourceContext",
					Values: []string{"namespace"},
				},
				{
					Name:   "destinationContext",
					Values: []string{"namespace"},
				},
			},
		}

		tcpHandler := &tcpHandler{}
		require.NoError(t, tcpHandler.Init(registry, opts))

		t.Run("ProcessSupportedFlagsFlow_"+tc.name, func(t *testing.T) {
			flow := buildFlow(tc.flags)
			_ = tcpHandler.ProcessFlow(t.Context(), flow)

			metricFamilies, err := registry.Gather()
			require.NoError(t, err)

			assert.Equal(t, "hubble_tcp_flags_total", *metricFamilies[0].Name)
			metric := metricFamilies[0].Metric[0]

			assert.Equal(t, "destination", *metric.Label[0].Name)
			assert.Equal(t, "bar", *metric.Label[0].Value)

			assert.Equal(t, "family", *metric.Label[1].Name)
			assert.Equal(t, "IPv4", *metric.Label[1].Value)

			assert.Equal(t, "flag", *metric.Label[2].Name)
			assert.Equal(t, tc.expectedLabel, *metric.Label[2].Value)

			assert.Equal(t, "source", *metric.Label[3].Name)
			assert.Equal(t, "foo", *metric.Label[3].Value)

			assert.Equal(t, 1., *metric.Counter.Value)

			//send another flow with same labels
			tcpHandler.ProcessFlow(t.Context(), flow)
			metricFamilies, _ = registry.Gather()
			metric = metricFamilies[0].Metric[0]
			assert.Equal(t, 2., *metric.Counter.Value)
		})

	}

	var unsupportedFlags = []struct {
		name  string
		flags ir.TCPFlags
	}{
		{"empty", ir.TCPFlags{}},
		{"PSH", ir.TCPFlags{PSH: true}},
		{"ACK", ir.TCPFlags{ACK: true}},
		{"URG", ir.TCPFlags{URG: true}},
		{"ECE", ir.TCPFlags{ECE: true}},
		{"CWR", ir.TCPFlags{CWR: true}},
		{"NS", ir.TCPFlags{NS: true}},
	}

	for _, tc := range unsupportedFlags {
		registry := prometheus.NewRegistry()
		opts := &api.MetricConfig{
			ContextOptionConfigs: []*api.ContextOptionConfig{
				{
					Name:   "sourceContext",
					Values: []string{"namespace"},
				},
				{
					Name:   "destinationContext",
					Values: []string{"namespace"},
				},
			},
		}

		tcpHandler := &tcpHandler{}
		require.NoError(t, tcpHandler.Init(registry, opts))

		t.Run("ProcessUnsupportedFlagsFlow_"+tc.name, func(t *testing.T) {
			flow := buildFlow(tc.flags)
			_ = tcpHandler.ProcessFlow(t.Context(), flow)

			metricFamilies, err := registry.Gather()
			require.NoError(t, err)
			require.Empty(t, metricFamilies)
		})

	}

}

func buildFlow(flags ir.TCPFlags) *ir.Flow {
	return &ir.Flow{
		EventType: ir.EventType{Type: monitorAPI.MessageTypePolicyVerdict},
		IP: ir.IP{
			IPVersion: pb.IPVersion_IPv4,
		},
		L4: ir.Layer4{
			TCP: ir.TCP{
				Flags: flags,
			},
		},
		Source:      ir.Endpoint{Namespace: "foo"},
		Destination: ir.Endpoint{Namespace: "bar"},
		Verdict:     pb.Verdict_FORWARDED,
	}
}
