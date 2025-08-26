// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package http

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

func Test_httpHandler_Status(t *testing.T) {
	plugin := httpPlugin{}
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
	assert.Equal(t, "destination=identity,source=namespace,exemplars=false", handler.Status())
}

func Test_httpHandler_ProcessFlow(t *testing.T) {
	ctx := t.Context()
	plugin := httpPlugin{}
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
	require.NoError(t, handler.Init(prometheus.NewRegistry(), &api.MetricConfig{}))

	// shouldn't count
	handler.ProcessFlow(ctx, &pb.Flow{})
	// shouldn't count
	handler.ProcessFlow(ctx, &pb.Flow{L7: &pb.Layer7{
		Type:   pb.L7FlowType_RESPONSE,
		Record: &pb.Layer7_Dns{},
	}})
	// should count for request
	handler.ProcessFlow(ctx, &pb.Flow{
		TrafficDirection: pb.TrafficDirection_INGRESS,
		L7: &pb.Layer7{
			Type: pb.L7FlowType_REQUEST,
			Record: &pb.Layer7_Http{Http: &pb.HTTP{
				Method: "GET",
			}},
		},
	})
	// should count for response
	handler.ProcessFlow(ctx, &pb.Flow{
		TrafficDirection: pb.TrafficDirection_INGRESS,
		L7: &pb.Layer7{
			Type:      pb.L7FlowType_RESPONSE,
			LatencyNs: 12345678,
			Record: &pb.Layer7_Http{Http: &pb.HTTP{
				Code:   200,
				Method: "GET",
			}},
		},
	})
	requestsExpected := `
        # HELP hubble_http_requests_total Count of HTTP requests
        # TYPE hubble_http_requests_total counter
	hubble_http_requests_total{method="GET",protocol="",reporter="server"} 1
	`
	require.NoError(t, testutil.CollectAndCompare(handler.(*httpHandler).requests, strings.NewReader(requestsExpected)))
	responsesExpected := `
       # HELP hubble_http_responses_total Count of HTTP responses
       # TYPE hubble_http_responses_total counter
       hubble_http_responses_total{method="GET",protocol="",reporter="server",status="200"} 1
	`
	require.NoError(t, testutil.CollectAndCompare(handler.(*httpHandler).responses, strings.NewReader(responsesExpected)))

	durationExpected := `
        # HELP hubble_http_request_duration_seconds Quantiles of HTTP request duration in seconds
        # TYPE hubble_http_request_duration_seconds histogram
        hubble_http_request_duration_seconds_bucket{method="GET",reporter="server",le="0.005"} 0
        hubble_http_request_duration_seconds_bucket{method="GET",reporter="server",le="0.01"} 0
        hubble_http_request_duration_seconds_bucket{method="GET",reporter="server",le="0.025"} 1
        hubble_http_request_duration_seconds_bucket{method="GET",reporter="server",le="0.05"} 1
        hubble_http_request_duration_seconds_bucket{method="GET",reporter="server",le="0.1"} 1
        hubble_http_request_duration_seconds_bucket{method="GET",reporter="server",le="0.25"} 1
        hubble_http_request_duration_seconds_bucket{method="GET",reporter="server",le="0.5"} 1
        hubble_http_request_duration_seconds_bucket{method="GET",reporter="server",le="1"} 1
        hubble_http_request_duration_seconds_bucket{method="GET",reporter="server",le="2.5"} 1
        hubble_http_request_duration_seconds_bucket{method="GET",reporter="server",le="5"} 1
        hubble_http_request_duration_seconds_bucket{method="GET",reporter="server",le="10"} 1
        hubble_http_request_duration_seconds_bucket{method="GET",reporter="server",le="+Inf"} 1
        hubble_http_request_duration_seconds_sum{method="GET",reporter="server"} 0.012345678
        hubble_http_request_duration_seconds_count{method="GET",reporter="server"} 1
	`
	require.NoError(t, testutil.CollectAndCompare(handler.(*httpHandler).duration, strings.NewReader(durationExpected)))
}

func Test_httpHandlerV2_ProcessFlow(t *testing.T) {
	ctx := t.Context()
	plugin := httpV2Plugin{}
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
	handler.ProcessFlow(ctx, &pb.Flow{
		TrafficDirection: pb.TrafficDirection_INGRESS,
		L7: &pb.Layer7{
			Type:   pb.L7FlowType_RESPONSE,
			Record: &pb.Layer7_Dns{},
		}})
	// shouldn't count for request, we use responses in v2
	handler.ProcessFlow(ctx, &pb.Flow{
		TrafficDirection: pb.TrafficDirection_INGRESS,
		L7: &pb.Layer7{
			Type: pb.L7FlowType_REQUEST,
			Record: &pb.Layer7_Http{Http: &pb.HTTP{
				Method: "GET",
			}},
		},
	})

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
		// Responses have the source and destination inverted, because it's the
		// other side of the flow. Our tests are asserting that the HTTPv2 handler
		// correctly inverts them so the source and destination are from the
		// perspective of the request.
		Source:      destinationEndpoint,
		Destination: sourceEndpoint,
		L7: &pb.Layer7{
			Type:      pb.L7FlowType_RESPONSE,
			LatencyNs: 12345678,
			Record: &pb.Layer7_Http{Http: &pb.HTTP{
				Protocol: "HTTP/1.1",
				Code:     200,
				Method:   "GET",
			}},
		},
	})
	requestsExpected := `
        # HELP hubble_http_requests_total Count of HTTP requests
        # TYPE hubble_http_requests_total counter
	      hubble_http_requests_total{destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",method="GET",protocol="HTTP/1.1",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",status="200"} 1
	`
	assert.NoError(t, testutil.CollectAndCompare(handler.(*httpHandler).requests, strings.NewReader(requestsExpected)))
	durationExpected := `
        # HELP hubble_http_request_duration_seconds Quantiles of HTTP request duration in seconds
        # TYPE hubble_http_request_duration_seconds histogram
        hubble_http_request_duration_seconds_bucket{destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",method="GET",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",le="0.005"} 0
        hubble_http_request_duration_seconds_bucket{destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",method="GET",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",le="0.01"} 0
        hubble_http_request_duration_seconds_bucket{destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",method="GET",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",le="0.025"} 1
        hubble_http_request_duration_seconds_bucket{destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",method="GET",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",le="0.05"} 1
        hubble_http_request_duration_seconds_bucket{destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",method="GET",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",le="0.1"} 1
        hubble_http_request_duration_seconds_bucket{destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",method="GET",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",le="0.25"} 1
        hubble_http_request_duration_seconds_bucket{destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",method="GET",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",le="0.5"} 1
        hubble_http_request_duration_seconds_bucket{destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",method="GET",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",le="1"} 1
        hubble_http_request_duration_seconds_bucket{destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",method="GET",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",le="2.5"} 1
        hubble_http_request_duration_seconds_bucket{destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",method="GET",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",le="5"} 1
        hubble_http_request_duration_seconds_bucket{destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",method="GET",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",le="10"} 1
        hubble_http_request_duration_seconds_bucket{destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",method="GET",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod",le="+Inf"} 1
        hubble_http_request_duration_seconds_sum{destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",method="GET",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod"} 0.012345678
        hubble_http_request_duration_seconds_count{destination="destination-ns/destination-deploy-pod",destination_pod="destination-deploy-pod",method="GET",reporter="server",source="source-ns/source-deploy-pod",source_pod="source-deploy-pod"} 1
	`
	require.NoError(t, testutil.CollectAndCompare(handler.(*httpHandler).duration, strings.NewReader(durationExpected)))
}

func Test_httpHandler_ListMetricVec(t *testing.T) {
	plugin := httpPlugin{}
	handler := plugin.NewHandler()
	require.NoError(t, handler.Init(prometheus.NewRegistry(), &api.MetricConfig{}))
	assert.Len(t, handler.ListMetricVec(), 3, "expecting 3 metrics, requests, responses and duration")
	for _, vec := range handler.ListMetricVec() {
		require.NotNil(t, vec, "ListMetricVec should not nil metrics vectors")
	}
}

func Test_httpV2Handler_ListMetricVec(t *testing.T) {
	plugin := httpV2Plugin{}
	handler := plugin.NewHandler()
	require.NoError(t, handler.Init(prometheus.NewRegistry(), &api.MetricConfig{}))
	assert.Len(t, handler.ListMetricVec(), 2, "expecting 2 metrics, requests and duration")
	for _, vec := range handler.ListMetricVec() {
		require.NotNil(t, vec, "ListMetricVec should not nil metrics vectors")
	}
}
