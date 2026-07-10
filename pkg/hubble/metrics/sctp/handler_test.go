// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package sctp

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

func TestSCTPHandler_Init(t *testing.T) {
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

	sctpHandler := &sctpHandler{}

	t.Run("Init", func(t *testing.T) {
		require.NoError(t, sctpHandler.Init(registry, opts))
	})

	t.Run("Status", func(t *testing.T) {
		require.Equal(t, "destination=namespace,source=namespace", sctpHandler.Status())
	})
}

func TestSCTPHandler(t *testing.T) {
	var supportedType = []struct {
		name          string
		types         pb.SCTPChunkType
		expectedLabel string
	}{
		{"INIT", pb.SCTPChunkType_INIT, "INIT"},
		{"INIT_ACK", pb.SCTPChunkType_INIT_ACK, "INIT_ACK"},
		{"SHUTDOWN", pb.SCTPChunkType_SHUTDOWN, "SHUTDOWN"},
		{"SHUTDOWN_ACK", pb.SCTPChunkType_SHUTDOWN_ACK, "SHUTDOWN_ACK"},
		{"SHUTDOWN_COMPLETE", pb.SCTPChunkType_SHUTDOWN_COMPLETE, "SHUTDOWN_COMPLETE"},
		{"ABORT", pb.SCTPChunkType_ABORT, "ABORT"},
	}

	for _, tc := range supportedType {
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

		sctpHandler := &sctpHandler{}
		require.NoError(t, sctpHandler.Init(registry, opts))

		t.Run("ProcessSupportedFlagsFlow_"+tc.name, func(t *testing.T) {
			flow := buildFlow(tc.types)
			_ = sctpHandler.ProcessFlow(t.Context(), flow)

			metricFamilies, err := registry.Gather()
			require.NoError(t, err)

			assert.Equal(t, "hubble_sctp_chunk_types_total", *metricFamilies[0].Name)
			metric := metricFamilies[0].Metric[0]

			assert.Equal(t, "chunk_type", *metric.Label[0].Name)
			assert.Equal(t, tc.expectedLabel, *metric.Label[0].Value)

			assert.Equal(t, "destination", *metric.Label[1].Name)
			assert.Equal(t, "bar", *metric.Label[1].Value)

			assert.Equal(t, "family", *metric.Label[2].Name)
			assert.Equal(t, "IPv4", *metric.Label[2].Value)

			assert.Equal(t, "source", *metric.Label[3].Name)
			assert.Equal(t, "foo", *metric.Label[3].Value)

			assert.Equal(t, 1., *metric.Counter.Value)

			// send another flow with same labels
			sctpHandler.ProcessFlow(t.Context(), flow)
			metricFamilies, _ = registry.Gather()
			metric = metricFamilies[0].Metric[0]
			assert.Equal(t, 2., *metric.Counter.Value)
		})
	}
}

func buildFlow(chunkType pb.SCTPChunkType) *pb.Flow {
	return &pb.Flow{
		EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
		IP: &pb.IP{
			IpVersion: pb.IPVersion_IPv4,
		},
		L4: &pb.Layer4{
			Protocol: &pb.Layer4_SCTP{
				SCTP: &pb.SCTP{
					ChunkType: chunkType,
				},
			},
		},
		Source:      &pb.Endpoint{Namespace: "foo"},
		Destination: &pb.Endpoint{Namespace: "bar"},
		Verdict:     pb.Verdict_FORWARDED,
	}
}
