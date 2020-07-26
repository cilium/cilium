// Copyright 2019 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package flow

import (
	"testing"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		flow := &testutils.FakeFlow{
			EventType: &pb.CiliumEventType{Type: monitorAPI.MessageTypeAccessLog},
			L7: &pb.Layer7{
				Record: &pb.Layer7_Http{Http: &pb.HTTP{}},
			},
			Source:      &pb.Endpoint{Namespace: "foo"},
			Destination: &pb.Endpoint{Namespace: "bar"},
			Verdict:     pb.Verdict_FORWARDED,
		}
		h.ProcessFlow(flow)

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
	})
}
