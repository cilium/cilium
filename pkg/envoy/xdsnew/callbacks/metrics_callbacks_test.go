// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"testing"
	"time"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/require"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/envoy/xds"
)

type recordedResponse struct {
	mode    string
	typeURL string
	size    int
	updated int
	removed int
}

type recordedAcknowledgement struct {
	mode     string
	typeURL  string
	status   string
	duration time.Duration
}

type recordingXDSTelemetry struct {
	responses        []recordedResponse
	acknowledgements []recordedAcknowledgement
	streams          int
}

var _ xds.Metrics = (*recordingXDSTelemetry)(nil)
var _ xds.Telemetry = (*recordingXDSTelemetry)(nil)

func (*recordingXDSTelemetry) IncreaseNACK(string)                             {}
func (*recordingXDSTelemetry) IncreaseACK(string)                              {}
func (*recordingXDSTelemetry) IncreaseCancel(string)                           {}
func (*recordingXDSTelemetry) ObserveUpdate(string, string, time.Duration)     {}
func (*recordingXDSTelemetry) ObserveSnapshotGeneration(string, time.Duration) {}

func (m *recordingXDSTelemetry) ObserveResponse(mode, typeURL string, size, updated, removed int) {
	m.responses = append(m.responses, recordedResponse{
		mode: mode, typeURL: typeURL, size: size, updated: updated, removed: removed,
	})
}

func (m *recordingXDSTelemetry) ObserveAcknowledgement(mode, typeURL, status string, duration time.Duration) {
	m.acknowledgements = append(m.acknowledgements, recordedAcknowledgement{
		mode: mode, typeURL: typeURL, status: status, duration: duration,
	})
}

func (m *recordingXDSTelemetry) IncreaseStream(string) { m.streams++ }
func (m *recordingXDSTelemetry) DecreaseStream(string) { m.streams-- }

func TestMetricsCallbacksDelta(t *testing.T) {
	metrics := &recordingXDSTelemetry{}
	callbacks := NewMetricsCallbacks("delta-ads", metrics)
	now := time.Unix(0, 0)
	callbacks.now = func() time.Time { return now }

	require.NoError(t, callbacks.OnDeltaStreamOpen(t.Context(), 7, ""))
	require.Equal(t, 1, metrics.streams)

	response := &discovery.DeltaDiscoveryResponse{
		TypeUrl:          "type.googleapis.com/test.Resource",
		Nonce:            "nonce-1",
		Resources:        []*discovery.Resource{{Name: "resource-1"}},
		RemovedResources: []string{"resource-2", "resource-3"},
	}
	callbacks.OnStreamDeltaResponse(7, nil, response)
	require.Equal(t, []recordedResponse{{
		mode: "delta-ads", typeURL: response.TypeUrl, size: proto.Size(response), updated: 1, removed: 2,
	}}, metrics.responses)

	now = now.Add(25 * time.Millisecond)
	require.NoError(t, callbacks.OnStreamDeltaRequest(7, &discovery.DeltaDiscoveryRequest{
		TypeUrl: response.TypeUrl, ResponseNonce: response.Nonce,
	}))
	require.Equal(t, []recordedAcknowledgement{{
		mode: "delta-ads", typeURL: response.TypeUrl, status: "ack", duration: 25 * time.Millisecond,
	}}, metrics.acknowledgements)

	now = now.Add(time.Millisecond)
	response.Nonce = "nonce-2"
	callbacks.OnStreamDeltaResponse(7, nil, response)
	now = now.Add(10 * time.Millisecond)
	require.NoError(t, callbacks.OnStreamDeltaRequest(7, &discovery.DeltaDiscoveryRequest{
		TypeUrl: response.TypeUrl, ResponseNonce: response.Nonce,
		ErrorDetail: &statuspb.Status{Message: "rejected"},
	}))
	require.Equal(t, "nack", metrics.acknowledgements[1].status)
	require.Equal(t, 10*time.Millisecond, metrics.acknowledgements[1].duration)

	response.Nonce = "nonce-3"
	callbacks.OnStreamDeltaResponse(7, nil, response)
	callbacks.OnDeltaStreamClosed(7, nil)
	require.Equal(t, 0, metrics.streams)
	require.NoError(t, callbacks.OnStreamDeltaRequest(7, &discovery.DeltaDiscoveryRequest{
		TypeUrl: response.TypeUrl, ResponseNonce: response.Nonce,
	}))
	require.Len(t, metrics.acknowledgements, 2)
}
