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
func (cb ChainedCallbacks) OnFetchRequest(ctx context.Context, req *discovery.DiscoveryRequest) error {
	for _, callback := range cb {
		if err := callback.OnFetchRequest(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// OnFetchResponse implements server.Callbacks.
func (cb ChainedCallbacks) OnFetchResponse(req *discovery.DiscoveryRequest, resp *discovery.DiscoveryResponse) {
	for _, callback := range cb {
		callback.OnFetchResponse(req, resp)
	}
}

// OnStreamDeltaRequest implements server.Callbacks.
func (cb ChainedCallbacks) OnStreamDeltaRequest(streamID int64, req *discovery.DeltaDiscoveryRequest) error {
	for _, callback := range cb {
		if err := callback.OnStreamDeltaRequest(streamID, req); err != nil {
			return err
		}
	}
	return nil
}

// OnStreamDeltaResponse implements server.Callbacks.
func (cb ChainedCallbacks) OnStreamDeltaResponse(streamID int64, req *discovery.DeltaDiscoveryRequest, resp *discovery.DeltaDiscoveryResponse) {
	for _, callback := range cb {
		callback.OnStreamDeltaResponse(streamID, req, resp)
	}
}

var _ envoy_xds.Callbacks = ChainedCallbacks{}

// OnStreamOpen is called once an xDS stream is open with a stream ID and the type URL (or "" for ADS).
// Returning an error will end processing and close the stream. OnStreamClosed will still be called.
func (chainedCbs ChainedCallbacks) OnStreamOpen(ctx context.Context, streamID int64, typ string) error {
	for _, cb := range chainedCbs {
		if err := cb.OnStreamOpen(ctx, streamID, typ); err != nil {
			return err
		}
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
		if err := cb.OnStreamRequest(streamID, req); err != nil {
			return err
		}
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
	for _, cb := range chainedCbs {
		if err := cb.OnDeltaStreamOpen(ctx, streamID, typeURL); err != nil {
			return err
		}
	}
	return nil
}

// OnDeltaStreamClosed invokes DeltaStreamClosedFunc.
func (chainedCbs ChainedCallbacks) OnDeltaStreamClosed(streamID int64, node *core.Node) {
	for _, cb := range chainedCbs {
		cb.OnDeltaStreamClosed(streamID, node)
	}
}
