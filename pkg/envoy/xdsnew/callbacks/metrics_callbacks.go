// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"sync"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	envoy_xds "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/envoy/xds"
)

type responseMetricKey struct {
	streamID int64
	typeURL  string
	nonce    string
}

type responseMetric struct {
	sentAt time.Time
}

// MetricsCallbacks records mode-aware response, stream, and ACK telemetry for
// the go-control-plane xDS server.
type MetricsCallbacks struct {
	mode    string
	metrics xds.Metrics
	now     func() time.Time

	mutex     sync.Mutex
	responses map[responseMetricKey]responseMetric
}

var _ envoy_xds.Callbacks = (*MetricsCallbacks)(nil)

func NewMetricsCallbacks(mode string, metrics xds.Metrics) *MetricsCallbacks {
	return &MetricsCallbacks{
		mode:      mode,
		metrics:   metrics,
		now:       time.Now,
		responses: make(map[responseMetricKey]responseMetric),
	}
}

func (cb *MetricsCallbacks) rememberResponse(streamID int64, typeURL, nonce string, size, updated, removed int) {
	xds.ObserveResponse(cb.metrics, cb.mode, typeURL, size, updated, removed)
	if nonce == "" {
		return
	}

	cb.mutex.Lock()
	cb.responses[responseMetricKey{streamID: streamID, typeURL: typeURL, nonce: nonce}] = responseMetric{sentAt: cb.now()}
	cb.mutex.Unlock()
}

func (cb *MetricsCallbacks) observeAcknowledgement(streamID int64, typeURL, nonce string, nack bool) {
	if nonce == "" {
		return
	}

	key := responseMetricKey{streamID: streamID, typeURL: typeURL, nonce: nonce}
	cb.mutex.Lock()
	response, found := cb.responses[key]
	if found {
		delete(cb.responses, key)
	}
	cb.mutex.Unlock()
	if found {
		xds.ObserveAcknowledgement(cb.metrics, cb.mode, typeURL, nack, cb.now().Sub(response.sentAt))
	}
}

func (cb *MetricsCallbacks) clearStream(streamID int64) {
	cb.mutex.Lock()
	for key := range cb.responses {
		if key.streamID == streamID {
			delete(cb.responses, key)
		}
	}
	cb.mutex.Unlock()
}

func (cb *MetricsCallbacks) OnFetchRequest(context.Context, *discovery.DiscoveryRequest) error {
	return nil
}

func (cb *MetricsCallbacks) OnFetchResponse(_ *discovery.DiscoveryRequest, response *discovery.DiscoveryResponse) {
	xds.ObserveResponse(cb.metrics, cb.mode, response.GetTypeUrl(), proto.Size(response), len(response.GetResources()), 0)
}

func (cb *MetricsCallbacks) OnStreamOpen(context.Context, int64, string) error {
	xds.IncreaseStream(cb.metrics, cb.mode)
	return nil
}

func (cb *MetricsCallbacks) OnStreamClosed(streamID int64, _ *core.Node) {
	cb.clearStream(streamID)
	xds.DecreaseStream(cb.metrics, cb.mode)
}

func (cb *MetricsCallbacks) OnStreamRequest(streamID int64, request *discovery.DiscoveryRequest) error {
	cb.observeAcknowledgement(streamID, request.GetTypeUrl(), request.GetResponseNonce(), request.GetErrorDetail() != nil)
	return nil
}

func (cb *MetricsCallbacks) OnStreamResponse(_ context.Context, streamID int64, _ *discovery.DiscoveryRequest, response *discovery.DiscoveryResponse) {
	cb.rememberResponse(streamID, response.GetTypeUrl(), response.GetNonce(), proto.Size(response), len(response.GetResources()), 0)
}

func (cb *MetricsCallbacks) OnDeltaStreamOpen(context.Context, int64, string) error {
	xds.IncreaseStream(cb.metrics, cb.mode)
	return nil
}

func (cb *MetricsCallbacks) OnDeltaStreamClosed(streamID int64, _ *core.Node) {
	cb.clearStream(streamID)
	xds.DecreaseStream(cb.metrics, cb.mode)
}

func (cb *MetricsCallbacks) OnStreamDeltaRequest(streamID int64, request *discovery.DeltaDiscoveryRequest) error {
	cb.observeAcknowledgement(streamID, request.GetTypeUrl(), request.GetResponseNonce(), request.GetErrorDetail() != nil)
	return nil
}

func (cb *MetricsCallbacks) OnStreamDeltaResponse(streamID int64, _ *discovery.DeltaDiscoveryRequest, response *discovery.DeltaDiscoveryResponse) {
	cb.rememberResponse(streamID, response.GetTypeUrl(), response.GetNonce(), proto.Size(response), len(response.GetResources()), len(response.GetRemovedResources()))
}
