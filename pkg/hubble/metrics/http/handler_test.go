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

package http

import (
	"strings"
	"testing"

	pb "github.com/cilium/cilium/api/v1/flow"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_httpHandler_Status(t *testing.T) {
	plugin := httpPlugin{}
	handler := plugin.NewHandler()
	assert.Equal(t, handler.Status(), "")
	options := map[string]string{"sourceContext": "namespace", "destinationContext": "identity"}
	require.NoError(t, handler.Init(prometheus.NewRegistry(), options))
	assert.Equal(t, handler.Status(), "destination=identity,source=namespace")
}

func Test_httpHandler_ProcessFlow(t *testing.T) {
	plugin := httpPlugin{}
	handler := plugin.NewHandler()
	require.Error(t, handler.Init(prometheus.NewRegistry(), map[string]string{"destinationContext": "invalid"}))
	require.NoError(t, handler.Init(prometheus.NewRegistry(), nil))
	// shouldn't count
	handler.ProcessFlow(&pb.Flow{})
	// shouldn't count
	handler.ProcessFlow(&pb.Flow{L7: &pb.Layer7{
		Type:   pb.L7FlowType_RESPONSE,
		Record: &pb.Layer7_Dns{},
	}})
	// should count for request
	handler.ProcessFlow(&pb.Flow{
		L7: &pb.Layer7{
			Type: pb.L7FlowType_REQUEST,
			Record: &pb.Layer7_Http{Http: &pb.HTTP{
				Method: "GET",
			}},
		},
	})
	// should count for response
	handler.ProcessFlow(&pb.Flow{
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
	hubble_http_requests_total{method="GET",protocol=""} 1
	`
	require.NoError(t, testutil.CollectAndCompare(handler.(*httpHandler).requests, strings.NewReader(requestsExpected)))
	responsesExpected := `
       # HELP hubble_http_responses_total Count of HTTP responses
       # TYPE hubble_http_responses_total counter
       hubble_http_responses_total{method="GET",status="200"} 1
	`
	require.NoError(t, testutil.CollectAndCompare(handler.(*httpHandler).responses, strings.NewReader(responsesExpected)))

	durationExpected := `
        # HELP hubble_http_request_duration_seconds Quantiles of HTTP request duration in seconds
        # TYPE hubble_http_request_duration_seconds histogram
        hubble_http_request_duration_seconds_bucket{method="GET",le="0.005"} 0
        hubble_http_request_duration_seconds_bucket{method="GET",le="0.01"} 0
        hubble_http_request_duration_seconds_bucket{method="GET",le="0.025"} 1
        hubble_http_request_duration_seconds_bucket{method="GET",le="0.05"} 1
        hubble_http_request_duration_seconds_bucket{method="GET",le="0.1"} 1
        hubble_http_request_duration_seconds_bucket{method="GET",le="0.25"} 1
        hubble_http_request_duration_seconds_bucket{method="GET",le="0.5"} 1
        hubble_http_request_duration_seconds_bucket{method="GET",le="1"} 1
        hubble_http_request_duration_seconds_bucket{method="GET",le="2.5"} 1
        hubble_http_request_duration_seconds_bucket{method="GET",le="5"} 1
        hubble_http_request_duration_seconds_bucket{method="GET",le="10"} 1
        hubble_http_request_duration_seconds_bucket{method="GET",le="+Inf"} 1
        hubble_http_request_duration_seconds_sum{method="GET"} 0.012345678
        hubble_http_request_duration_seconds_count{method="GET"} 1
	`
	require.NoError(t, testutil.CollectAndCompare(handler.(*httpHandler).duration, strings.NewReader(durationExpected)))
}
