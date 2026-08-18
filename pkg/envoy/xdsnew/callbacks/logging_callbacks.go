// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"log/slog"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	envoy_xds "github.com/envoyproxy/go-control-plane/pkg/server/v3"

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
func (cb LoggingCallbacks) OnStreamDeltaRequest(streamID int64, req *discovery.DeltaDiscoveryRequest) error {
	args := []any{
		logfields.XDSStreamID, streamID,
		logfields.XDSTypeURL, req.GetTypeUrl(),
		logfields.XDSNonce, req.GetResponseNonce(),
		logfields.XDSResourceNames, req.GetResourceNamesSubscribe(),
		logfields.XDSResourceNamesUnsubscribe, req.GetResourceNamesUnsubscribe(),
	}
	if req.GetErrorDetail() != nil {
		args = append(args, logfields.Error, req.GetErrorDetail().GetMessage())
	}
	cb.Log.Info("OnStreamDeltaRequest", args...)
	return nil
}

// OnStreamDeltaResponse implements server.Callbacks.
func (cb LoggingCallbacks) OnStreamDeltaResponse(streamID int64, req *discovery.DeltaDiscoveryRequest, resp *discovery.DeltaDiscoveryResponse) {
	cb.Log.Info("OnStreamDeltaResponse",
		logfields.XDSStreamID, streamID,
		logfields.XDSVersion, resp.GetSystemVersionInfo(),
		logfields.XDSTypeURL, resp.GetTypeUrl(),
		logfields.XDSNonce, resp.GetNonce(),
		logfields.XDSNumResources, len(resp.GetResources()),
		logfields.XDSRemovedResources, resp.GetRemovedResources())
}

var _ envoy_xds.Callbacks = LoggingCallbacks{}

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
	cb.Log.Info("OnDeltaStreamOpen",
		logfields.XDSStreamID, streamID,
		logfields.XDSTypeURL, typeURL)
	return nil
}

// OnDeltaStreamClosed invokes DeltaStreamClosedFunc.
func (cb LoggingCallbacks) OnDeltaStreamClosed(streamID int64, node *core.Node) {
	cb.Log.Info("OnDeltaStreamClosed",
		logfields.XDSStreamID, streamID)
}
