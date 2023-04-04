// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package drop

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

func TestDropHandler(t *testing.T) {
	registry := prometheus.NewRegistry()
	opts := api.Options{"sourceContext": "namespace", "destinationContext": "namespace"}

	dropHandler := &dropHandler{}

	t.Run("Init", func(t *testing.T) {
		require.NoError(t, dropHandler.Init(registry, opts))
	})

	t.Run("Status", func(t *testing.T) {
		require.Equal(t, "destination=namespace,source=namespace", dropHandler.Status())
	})

	t.Run("ProcessFlow_ShouldReportNothingForForwardedFlow", func(t *testing.T) {
		flow := &pb.Flow{
			EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
			L4: &pb.Layer4{
				Protocol: &pb.Layer4_TCP{
					TCP: &pb.TCP{},
				},
			},
			Source:      &pb.Endpoint{Namespace: "foo"},
			Destination: &pb.Endpoint{Namespace: "bar"},
			Verdict:     pb.Verdict_FORWARDED,
		}
		dropHandler.ProcessFlow(context.TODO(), flow)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)
		require.Empty(t, metricFamilies)

	})

	t.Run("ProcessFlow_ShouldReportDroppedFlow", func(t *testing.T) {
		flow := &pb.Flow{
			EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
			L4: &pb.Layer4{
				Protocol: &pb.Layer4_TCP{
					TCP: &pb.TCP{},
				},
			},
			Source:         &pb.Endpoint{Namespace: "foo"},
			Destination:    &pb.Endpoint{Namespace: "bar"},
			Verdict:        pb.Verdict_DROPPED,
			DropReason:     uint32(pb.DropReason_POLICY_DENIED),
			DropReasonDesc: pb.DropReason_POLICY_DENIED,
		}
		dropHandler.ProcessFlow(context.TODO(), flow)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		assert.Equal(t, "hubble_drop_total", *metricFamilies[0].Name)
		require.Len(t, metricFamilies[0].Metric, 1)
		metric := metricFamilies[0].Metric[0]

		assert.Equal(t, "destination", *metric.Label[0].Name)
		assert.Equal(t, "bar", *metric.Label[0].Value)

		assert.Equal(t, "protocol", *metric.Label[1].Name)
		assert.Equal(t, "TCP", *metric.Label[1].Value)

		assert.Equal(t, "reason", *metric.Label[2].Name)
		assert.Equal(t, "POLICY_DENIED", *metric.Label[2].Value)

		assert.Equal(t, "source", *metric.Label[3].Name)
		assert.Equal(t, "foo", *metric.Label[3].Value)

		assert.Equal(t, 1., *metric.Counter.Value)

		//send another flow with same labels
		dropHandler.ProcessFlow(context.TODO(), flow)
		metricFamilies, _ = registry.Gather()
		metric = metricFamilies[0].Metric[0]
		assert.Equal(t, 2., *metric.Counter.Value)
	})
}
