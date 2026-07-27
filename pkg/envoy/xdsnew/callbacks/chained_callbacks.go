// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	envoy_xds "github.com/envoyproxy/go-control-plane/pkg/server/v3"
)

type ChainedCallbacks []envoy_xds.Callbacks

// OnFetchRequest implements server.Callbacks.
func (cb ChainedCallbacks) OnFetchRequest(context.Context, *discovery.DiscoveryRequest) error {
	return nil
}

// OnFetchResponse implements server.Callbacks.
func (cb ChainedCallbacks) OnFetchResponse(*discovery.DiscoveryRequest, *discovery.DiscoveryResponse) {
}

// OnStreamDeltaRequest implements server.Callbacks.
func (cb ChainedCallbacks) OnStreamDeltaRequest(int64, *discovery.DeltaDiscoveryRequest) error {
	return nil
}

// OnStreamDeltaResponse implements server.Callbacks.
func (cb ChainedCallbacks) OnStreamDeltaResponse(int64, *discovery.DeltaDiscoveryRequest, *discovery.DeltaDiscoveryResponse) {
}

var _ envoy_xds.Callbacks = ChainedCallbacks{}

// OnStreamOpen is called once an xDS stream is open with a stream ID and the type URL (or "" for ADS).
// Returning an error will end processing and close the stream. OnStreamClosed will still be called.
func (chainedCbs ChainedCallbacks) OnStreamOpen(ctx context.Context, streamID int64, typ string) error {
	for _, cb := range chainedCbs {
		cb.OnStreamOpen(ctx, streamID, typ)
	}
	return nil
}

// OnStreamClosed is called immediately prior to closing an xDS stream with a stream ID.
func (chainedCbs ChainedCallbacks) OnStreamClosed(streamID int64, node *core.Node) {
	for _, cb := range chainedCbs {
		cb.OnStreamClosed(streamID, node)
	}
}

// OnStreamRequest is called once a request is received on a stream.
// Returning an error will end processing and close the stream. OnStreamClosed will still be called.
func (chainedCbs ChainedCallbacks) OnStreamRequest(streamID int64, req *discovery.DiscoveryRequest) error {
	for _, cb := range chainedCbs {
		cb.OnStreamRequest(streamID, req)
	}
	return nil
}

// OnStreamResponse is called immediately prior to sending a response on a stream.
func (chainedCbs ChainedCallbacks) OnStreamResponse(ctx context.Context, streamID int64, req *discovery.DiscoveryRequest, resp *discovery.DiscoveryResponse) {
	for _, cb := range chainedCbs {
		cb.OnStreamResponse(ctx, streamID, req, resp)
	}
}

func (chainedCbs ChainedCallbacks) OnDeltaStreamOpen(ctx context.Context, streamID int64, typeURL string) error {
	return nil
}

// OnDeltaStreamClosed invokes DeltaStreamClosedFunc.
func (chainedCbs ChainedCallbacks) OnDeltaStreamClosed(streamID int64, node *core.Node) {
}
