// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	sotw "github.com/envoyproxy/go-control-plane/pkg/server/sotw/v3"

	"github.com/cilium/cilium/pkg/envoy/xds"
)

// MetricsCallbacks records the ACK and NACK responses Envoy sends on an ADS
// stream, so that cilium_xds_events_count is populated in ADS mode the same way
// the per-resource-type xDS server populates it.
type MetricsCallbacks struct {
	Metrics xds.Metrics
}

var _ sotw.Callbacks = MetricsCallbacks{}

// OnStreamRequest implements server.Callbacks.
//
// A request carrying a version is an acknowledgement of the response Envoy was
// last sent: with an error detail it is a NACK, without one an ACK. Requests
// with no version are the initial subscription and are not counted.
func (cb MetricsCallbacks) OnStreamRequest(streamID int64, req *discovery.DiscoveryRequest) error {
	if cb.Metrics == nil || req.GetVersionInfo() == "" {
		return nil
	}
	if req.GetErrorDetail() != nil {
		cb.Metrics.IncreaseNACK(req.GetTypeUrl())
	} else {
		cb.Metrics.IncreaseACK(req.GetTypeUrl())
	}
	return nil
}

// OnFetchRequest implements server.Callbacks.
func (cb MetricsCallbacks) OnFetchRequest(context.Context, *discovery.DiscoveryRequest) error {
	return nil
}

// OnFetchResponse implements server.Callbacks.
func (cb MetricsCallbacks) OnFetchResponse(*discovery.DiscoveryRequest, *discovery.DiscoveryResponse) {
}

// OnStreamDeltaRequest implements server.Callbacks.
func (cb MetricsCallbacks) OnStreamDeltaRequest(int64, *discovery.DeltaDiscoveryRequest) error {
	return nil
}

// OnStreamDeltaResponse implements server.Callbacks.
func (cb MetricsCallbacks) OnStreamDeltaResponse(int64, *discovery.DeltaDiscoveryRequest, *discovery.DeltaDiscoveryResponse) {
}

// OnStreamOpen implements server.Callbacks.
func (cb MetricsCallbacks) OnStreamOpen(context.Context, int64, string) error {
	return nil
}

// OnStreamClosed implements server.Callbacks.
func (cb MetricsCallbacks) OnStreamClosed(int64, *core.Node) {
}

// OnStreamResponse implements server.Callbacks.
func (cb MetricsCallbacks) OnStreamResponse(context.Context, int64, *discovery.DiscoveryRequest, *discovery.DiscoveryResponse) {
}

// OnDeltaStreamOpen implements server.Callbacks.
func (cb MetricsCallbacks) OnDeltaStreamOpen(context.Context, int64, string) error {
	return nil
}

// OnDeltaStreamClosed implements server.Callbacks.
func (cb MetricsCallbacks) OnDeltaStreamClosed(int64, *core.Node) {
}
