// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"log/slog"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	sotw "github.com/envoyproxy/go-control-plane/pkg/server/sotw/v3"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

type LoggingCallbacks struct {
	Log *slog.Logger
}

// OnFetchRequest implements server.Callbacks.
func (cb LoggingCallbacks) OnFetchRequest(context.Context, *discovery.DiscoveryRequest) error {
	return nil
}

// OnFetchResponse implements server.Callbacks.
func (cb LoggingCallbacks) OnFetchResponse(*discovery.DiscoveryRequest, *discovery.DiscoveryResponse) {
}

// OnStreamDeltaRequest implements server.Callbacks.
func (cb LoggingCallbacks) OnStreamDeltaRequest(int64, *discovery.DeltaDiscoveryRequest) error {
	return nil
}

// OnStreamDeltaResponse implements server.Callbacks.
func (cb LoggingCallbacks) OnStreamDeltaResponse(int64, *discovery.DeltaDiscoveryRequest, *discovery.DeltaDiscoveryResponse) {
}

var _ sotw.Callbacks = LoggingCallbacks{}

// OnStreamOpen is called once an xDS stream is open with a stream ID and the type URL (or "" for ADS).
// Returning an error will end processing and close the stream. OnStreamClosed will still be called.
func (cb LoggingCallbacks) OnStreamOpen(ctx context.Context, streamID int64, typ string) error {
	cb.Log.Info("OnStreamOpen",
		logfields.XDSStreamID, streamID,
		logfields.XDSTypeURL, typ)
	return nil
}

// OnStreamClosed is called immediately prior to closing an xDS stream with a stream ID.
func (cb LoggingCallbacks) OnStreamClosed(streamID int64, node *core.Node) {
	cb.Log.Info("OnStreamClosed",
		logfields.XDSStreamID, streamID)
}

// OnStreamRequest is called once a request is received on a stream.
// Returning an error will end processing and close the stream. OnStreamClosed will still be called.
func (cb LoggingCallbacks) OnStreamRequest(streamID int64, req *discovery.DiscoveryRequest) error {
	cb.Log.Info("OnStreamRequest",
		logfields.XDSStreamID, streamID,
		logfields.XDSVersion, req.GetVersionInfo(),
		logfields.XDSTypeURL, req.GetTypeUrl(),
		logfields.XDSNonce, req.GetResponseNonce(),
		logfields.XDSResourceNames, req.GetResourceNames())
	return nil
}

// OnStreamResponse is called immediately prior to sending a response on a stream.
func (cb LoggingCallbacks) OnStreamResponse(ctx context.Context, streamID int64, req *discovery.DiscoveryRequest, resp *discovery.DiscoveryResponse) {
	cb.Log.Info("OnStreamResponse",
		logfields.XDSStreamID, streamID,
		logfields.XDSVersion, resp.GetVersionInfo(),
		logfields.XDSTypeURL, resp.GetTypeUrl(),
		logfields.XDSNumResources, len(resp.GetResources()))
}

func (cb LoggingCallbacks) OnDeltaStreamOpen(ctx context.Context, streamID int64, typeURL string) error {
	return nil
}

// OnDeltaStreamClosed invokes DeltaStreamClosedFunc.
func (cb LoggingCallbacks) OnDeltaStreamClosed(streamID int64, node *core.Node) {
}
