// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package flow

import (
	"context"
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
	opts := api.Options{"sourceContext": "namespace", "destinationContext": "namespace"}

	h := &flowHandler{}

	t.Run("Init", func(t *testing.T) {
		require.NoError(t, h.Init(registry, opts))
	})

	t.Run("Status", func(t *testing.T) {
		require.Equal(t, "destination=namespace,source=namespace", h.Status())
	})

	t.Run("ProcessFlow", func(t *testing.T) {
		flow1 := &pb.Flow{
			EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypeAccessLog},
			L7: &pb.Layer7{
				Record: &pb.Layer7_Http{Http: &pb.HTTP{}},
			},
			Source:      &pb.Endpoint{Namespace: "foo"},
			Destination: &pb.Endpoint{Namespace: "bar"},
			Verdict:     pb.Verdict_FORWARDED,
		}
		h.ProcessFlow(context.TODO(), flow1)

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
		assert.Equal(t, "foo", *metric.Label[2].Value)

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
		}

		h.ProcessFlow(context.TODO(), flow2)

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
		}

		h.ProcessFlow(context.TODO(), flow3)

		metricFamilies, err = registry.Gather()
		require.NoError(t, err)
		require.Len(t, metricFamilies, 1)

		assert.Equal(t, "hubble_flows_processed_total", *metricFamilies[0].Name)
		require.Len(t, metricFamilies[0].Metric, 3)
		metric = metricFamilies[0].Metric[0]

		assert.Equal(t, "protocol", *metric.Label[1].Name)
		assert.Equal(t, "UDP", *metric.Label[1].Value)

		assert.Equal(t, "subtype", *metric.Label[3].Name)
		assert.Equal(t, "", *metric.Label[3].Value)

		assert.Equal(t, "type", *metric.Label[4].Name)
		assert.Equal(t, "PolicyVerdict", *metric.Label[4].Value)

		assert.Equal(t, "verdict", *metric.Label[5].Name)
		assert.Equal(t, "DROPPED", *metric.Label[5].Value)
	})

}
