// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package portdistribution

import (
	"context"
	"testing"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

func TestPortDistributionHandler(t *testing.T) {
	registry := prometheus.NewRegistry()
	opts := api.Options{"sourceContext": "namespace", "destinationContext": "namespace"}

	portHandler := &portDistributionHandler{}

	t.Run("Init", func(t *testing.T) {
		require.NoError(t, portHandler.Init(registry, opts))
	})

	t.Run("Status", func(t *testing.T) {
		require.Equal(t, "destination=namespace,source=namespace", portHandler.Status())
	})

	t.Run("ProcessFlow_SkipReply", func(t *testing.T) {
		flow := buildFlow(8080, pb.Verdict_FORWARDED, true)
		portHandler.ProcessFlow(context.TODO(), flow)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		require.Empty(t, metricFamilies)
	})

	t.Run("ProcessFlow_SkipDropped", func(t *testing.T) {
		flow := buildFlow(8080, pb.Verdict_DROPPED, false)
		portHandler.ProcessFlow(context.TODO(), flow)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		require.Empty(t, metricFamilies)
	})

	t.Run("ProcessFlow", func(t *testing.T) {
		flow := buildFlow(8080, pb.Verdict_FORWARDED, false)
		portHandler.ProcessFlow(context.TODO(), flow)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		assert.Equal(t, "hubble_port_distribution_total", *metricFamilies[0].Name)
		require.Len(t, metricFamilies[0].Metric, 1)
		metric := metricFamilies[0].Metric[0]

		assert.Equal(t, "destination", *metric.Label[0].Name)
		assert.Equal(t, "bar", *metric.Label[0].Value)

		assert.Equal(t, "port", *metric.Label[1].Name)
		assert.Equal(t, "8080", *metric.Label[1].Value)

		assert.Equal(t, "protocol", *metric.Label[2].Name)
		assert.Equal(t, "TCP", *metric.Label[2].Value)

		assert.Equal(t, "source", *metric.Label[3].Name)
		assert.Equal(t, "foo", *metric.Label[3].Value)

		assert.Equal(t, 1., *metric.Counter.Value)

		//send another flow with same labels
		portHandler.ProcessFlow(context.TODO(), flow)
		metricFamilies, _ = registry.Gather()
		metric = metricFamilies[0].Metric[0]
		assert.Equal(t, 2., *metric.Counter.Value)
	})

	t.Run("ProcessFlow_MultiplePorts", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		opts := api.Options{"sourceContext": "namespace", "destinationContext": "namespace"}

		portHandler := &portDistributionHandler{}
		require.NoError(t, portHandler.Init(registry, opts))

		flow1 := buildFlow(8081, pb.Verdict_FORWARDED, false)
		portHandler.ProcessFlow(context.TODO(), flow1)

		flow2 := buildFlow(8082, pb.Verdict_FORWARDED, false)
		portHandler.ProcessFlow(context.TODO(), flow2)
		portHandler.ProcessFlow(context.TODO(), flow2)

		metricFamilies, err := registry.Gather()
		require.NoError(t, err)

		assert.Equal(t, "hubble_port_distribution_total", *metricFamilies[0].Name)
		require.Len(t, metricFamilies[0].Metric, 2)

		for _, metric := range metricFamilies[0].Metric {
			switch *metric.Label[1].Value {
			case "8081":
				assert.Equal(t, 1., *metric.Counter.Value)
			case "8082":
				assert.Equal(t, 2., *metric.Counter.Value)
			}
		}
	})

}

func buildFlow(port uint32, verdict pb.Verdict, reply bool) *pb.Flow {
	return &pb.Flow{
		EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
		L4: &pb.Layer4{
			Protocol: &pb.Layer4_TCP{
				TCP: &pb.TCP{
					DestinationPort: port,
				},
			},
		},
		Source:      &pb.Endpoint{Namespace: "foo"},
		Destination: &pb.Endpoint{Namespace: "bar"},
		Verdict:     verdict,
		IsReply:     &wrappers.BoolValue{Value: reply},
	}
}
