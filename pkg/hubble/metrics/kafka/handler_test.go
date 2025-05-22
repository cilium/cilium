// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package kafka

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

func Test_kafkaHandler_Status(t *testing.T) {
	plugin := kafkaPlugin{}
	handler := plugin.NewHandler()
	assert.Empty(t, handler.Status())
	options := &api.MetricConfig{
		ContextOptionConfigs: []*api.ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"namespace"},
			},
			{
				Name:   "destinationContext",
				Values: []string{"identity"},
			},
		},
	}
	require.NoError(t, handler.Init(prometheus.NewRegistry(), options))
	assert.Equal(t, "destination=identity,source=namespace", handler.Status())
}

func Test_kafkaHandler_ProcessFlow(t *testing.T) {
	ctx := t.Context()
	plugin := kafkaPlugin{}
	handler := plugin.NewHandler()
	options := &api.MetricConfig{
		ContextOptionConfigs: []*api.ContextOptionConfig{
			{
				Name:   "destinationContext",
				Values: []string{"invalid"},
			},
		},
	}
	require.Error(t, handler.Init(prometheus.NewRegistry(), options))
	options = &api.MetricConfig{
		ContextOptionConfigs: []*api.ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"pod"},
			},
			{
				Name:   "destinationContext",
				Values: []string{"pod"},
			},
			{
				Name:   "labelsContext",
				Values: []string{"source_pod", "destination_pod"},
			},
		},
	}
	require.NoError(t, handler.Init(prometheus.NewRegistry(), options))
	// shouldn't count
	handler.ProcessFlow(ctx, &pb.Flow{})
	// shouldn't count
	handler.ProcessFlow(ctx, &pb.Flow{L7: &pb.Layer7{
		Type:   pb.L7FlowType_RESPONSE,
		Record: &pb.Layer7_Dns{},
	}})
	sourceEndpoint := &pb.Endpoint{
		Namespace: "source-ns",
		PodName:   "source-deploy-pod",
		Workloads: []*pb.Workload{{
			Name: "source-deploy",
			Kind: "Deployment",
		}},
		Labels: []string{
			"k8s:app=sourceapp",
		},
	}
	destinationEndpoint := &pb.Endpoint{
		Namespace: "destination-ns",
		PodName:   "destination-deploy-pod",
		Workloads: []*pb.Workload{{
			Name: "destination-deploy",
			Kind: "Deployment",
		}},
		Labels: []string{
			"k8s:app=destinationapp",
		},
	}
	// should count for request
	handler.ProcessFlow(ctx, &pb.Flow{
		TrafficDirection: pb.TrafficDirection_INGRESS,
		Source:           sourceEndpoint,
		Destination:      destinationEndpoint,
		L7: &pb.Layer7{
			Type:      pb.L7FlowType_REQUEST,
			LatencyNs: 12345678,
			Record: &pb.Layer7_Kafka{Kafka: &pb.Kafka{
				Topic:     "test-topic",
				ApiKey:    "test-api-key",
				ErrorCode: 0,
			}},
		},
	})
	requestsExpected := `
        # HELP hubble_kafka_requests_total Count of Kafka requests
        # TYPE hubble_kafka_requests_total counter
	      hubble_kafka_requests_total{api_key="test-api-key", destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",error_code="0",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",topic="test-topic"} 1
	`
	assert.NoError(t, testutil.CollectAndCompare(handler.(*kafkaHandler).requests, strings.NewReader(requestsExpected)))
	durationExpected := `
        # HELP hubble_kafka_request_duration_seconds Quantiles of HTTP request duration in seconds
        # TYPE hubble_kafka_request_duration_seconds histogram
        hubble_kafka_request_duration_seconds_bucket{api_key="test-api-key",destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",topic="test-topic",le="0.005"} 0
        hubble_kafka_request_duration_seconds_bucket{api_key="test-api-key",destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",topic="test-topic",le="0.01"} 0
        hubble_kafka_request_duration_seconds_bucket{api_key="test-api-key",destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",topic="test-topic",le="0.025"} 1
        hubble_kafka_request_duration_seconds_bucket{api_key="test-api-key",destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",topic="test-topic",le="0.05"} 1
        hubble_kafka_request_duration_seconds_bucket{api_key="test-api-key",destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",topic="test-topic",le="0.1"} 1
        hubble_kafka_request_duration_seconds_bucket{api_key="test-api-key",destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",topic="test-topic",le="0.25"} 1
        hubble_kafka_request_duration_seconds_bucket{api_key="test-api-key",destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",topic="test-topic",le="0.5"} 1
        hubble_kafka_request_duration_seconds_bucket{api_key="test-api-key",destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",topic="test-topic",le="1"} 1
        hubble_kafka_request_duration_seconds_bucket{api_key="test-api-key",destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",topic="test-topic",le="2.5"} 1
        hubble_kafka_request_duration_seconds_bucket{api_key="test-api-key",destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",topic="test-topic",le="5"} 1
        hubble_kafka_request_duration_seconds_bucket{api_key="test-api-key",destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",topic="test-topic",le="10"} 1
        hubble_kafka_request_duration_seconds_bucket{api_key="test-api-key",destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",topic="test-topic",le="+Inf"} 1
        hubble_kafka_request_duration_seconds_sum{api_key="test-api-key",destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",topic="test-topic"} 0.012345678
        hubble_kafka_request_duration_seconds_count{api_key="test-api-key",destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",topic="test-topic"} 1
	`
	require.NoError(t, testutil.CollectAndCompare(handler.(*kafkaHandler).duration, strings.NewReader(durationExpected)))
}

func Test_kafkaHandler_ListMetricVec(t *testing.T) {
	plugin := kafkaPlugin{}
	handler := plugin.NewHandler()
	require.NoError(t, handler.Init(prometheus.NewRegistry(), &api.MetricConfig{}))
	assert.Len(t, handler.ListMetricVec(), 2, "expecting 2 metrics, requests and duration")
	for _, vec := range handler.ListMetricVec() {
		require.NotNil(t, vec, "ListMetricVec should not nil metrics vectors")
	}
}
