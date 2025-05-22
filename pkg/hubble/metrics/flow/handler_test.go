// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package flow

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

func TestFlowHandler(t *testing.T) {
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
		IncludeFilters: []*pb.FlowFilter{
			{SourcePod: []string{"allowNs/"}},
		},
	}

	h := &flowHandler{}

	t.Run("Init", func(t *testing.T) {
		require.NoError(t, h.Init(registry, opts))
	})

	t.Run("Status", func(t *testing.T) {
		require.Equal(t, "destination=namespace,source=namespace", h.Status())
	})

	t.Run("ProcessFlow", func(t *testing.T) {
		flow0 := &pb.Flow{
			EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypeAccessLog},
			L7: &pb.Layer7{
				Record: &pb.Layer7_Http{Http: &pb.HTTP{}},
			},
			Source:      &pb.Endpoint{Namespace: "foo"},
			Destination: &pb.Endpoint{Namespace: "bar"},
			Verdict:     pb.Verdict_FORWARDED,
		}
		flow1 := &pb.Flow{
			EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypeAccessLog},
			L7: &pb.Layer7{
				Record: &pb.Layer7_Http{Http: &pb.HTTP{}},
			},
			Source:      &pb.Endpoint{Namespace: "allowNs"},
			Destination: &pb.Endpoint{Namespace: "bar"},
			Verdict:     pb.Verdict_FORWARDED,
		}
		h.ProcessFlow(t.Context(), flow0)
		h.ProcessFlow(t.Context(), flow1)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 1)

		assert.Equal(t, "hubble_flows_processed_total", *metricFamilies[0].Name)
		require.Len(t, metricFamilies[0].Metric, 1)
		metric := metricFamilies[0].Metric[0]

		assert.Equal(t, "destination", *metric.Label[0].Name)
		assert.Equal(t, "bar", *metric.Label[0].Value)

		assert.Equal(t, "protocol", *metric.Label[1].Name)
		assert.Equal(t, "HTTP", *metric.Label[1].Value)

		assert.Equal(t, "source", *metric.Label[2].Name)
		assert.Equal(t, "allowNs", *metric.Label[2].Value)

		assert.Equal(t, "subtype", *metric.Label[3].Name)
		assert.Equal(t, "HTTP", *metric.Label[3].Value)

		assert.Equal(t, "type", *metric.Label[4].Name)
		assert.Equal(t, "L7", *metric.Label[4].Value)

		assert.Equal(t, "verdict", *metric.Label[5].Name)
		assert.Equal(t, "FORWARDED", *metric.Label[5].Value)

		flow2 := &pb.Flow{
			EventType: &pb.CiliumEventType{
				// flow events cannot be derived from agent events
				Type: monitorAPI.MessageTypeAgent,
			},
			Source: &pb.Endpoint{Namespace: "allowNs"},
		}

		h.ProcessFlow(t.Context(), flow2)

		metricFamilies, err = registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 1)

		assert.Equal(t, "hubble_flows_processed_total", *metricFamilies[0].Name)
		require.Len(t, metricFamilies[0].Metric, 2)
		metric = metricFamilies[0].Metric[0]

		assert.Equal(t, "subtype", *metric.Label[3].Name)
		assert.Equal(t, "130", *metric.Label[3].Value)

		assert.Equal(t, "type", *metric.Label[4].Name)
		assert.Equal(t, "Unknown", *metric.Label[4].Value)

		flow3 := &pb.Flow{
			EventType: &pb.CiliumEventType{
				Type: monitorAPI.MessageTypePolicyVerdict,
			},
			L4: &pb.Layer4{
				Protocol: &pb.Layer4_UDP{
					UDP: &pb.UDP{
						DestinationPort: 53,
						SourcePort:      31313,
					},
				},
			},
			Verdict: pb.Verdict_DROPPED,
			Source:  &pb.Endpoint{Namespace: "allowNs"},
		}

		h.ProcessFlow(t.Context(), flow3)

		metricFamilies, err = registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 1)

		assert.Equal(t, "hubble_flows_processed_total", *metricFamilies[0].Name)
		require.Len(t, metricFamilies[0].Metric, 3)
		metric = metricFamilies[0].Metric[0]

		assert.Equal(t, "protocol", *metric.Label[1].Name)
		assert.Equal(t, "UDP", *metric.Label[1].Value)

		assert.Equal(t, "subtype", *metric.Label[3].Name)
		assert.Empty(t, *metric.Label[3].Value)

		assert.Equal(t, "type", *metric.Label[4].Name)
		assert.Equal(t, "PolicyVerdict", *metric.Label[4].Value)

		assert.Equal(t, "verdict", *metric.Label[5].Name)
		assert.Equal(t, "DROPPED", *metric.Label[5].Value)
	})

}
