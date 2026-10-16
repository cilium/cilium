// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"errors"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	server "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/stretchr/testify/require"
)

func TestChainedCallbacksPropagatesErrors(t *testing.T) {
	tests := []struct {
		name string
		call func(ChainedCallbacks) error
	}{
		{"stream-open", func(c ChainedCallbacks) error { return c.OnStreamOpen(t.Context(), 1, "type") }},
		{"stream-request", func(c ChainedCallbacks) error { return c.OnStreamRequest(1, &discovery.DiscoveryRequest{}) }},
		{"delta-stream-open", func(c ChainedCallbacks) error { return c.OnDeltaStreamOpen(t.Context(), 1, "type") }},
		{"delta-stream-request", func(c ChainedCallbacks) error { return c.OnStreamDeltaRequest(1, &discovery.DeltaDiscoveryRequest{}) }},
		{"fetch-request", func(c ChainedCallbacks) error { return c.OnFetchRequest(t.Context(), &discovery.DiscoveryRequest{}) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, failAt := range []int{-1, 0, 1, 2} {
				var calls []int
				failure := errors.New("callback failed")
				var chain ChainedCallbacks
				for i := range 3 {
					callback := func() error {
						calls = append(calls, i)
						if i == failAt {
							return failure
						}
						return nil
					}
					chain = append(chain, server.CallbackFuncs{
						StreamOpenFunc:         func(context.Context, int64, string) error { return callback() },
						StreamRequestFunc:      func(int64, *discovery.DiscoveryRequest) error { return callback() },
						DeltaStreamOpenFunc:    func(context.Context, int64, string) error { return callback() },
						StreamDeltaRequestFunc: func(int64, *discovery.DeltaDiscoveryRequest) error { return callback() },
						FetchRequestFunc:       func(context.Context, *discovery.DiscoveryRequest) error { return callback() },
					})
				}
				err := test.call(chain)
				if failAt < 0 {
					require.NoError(t, err)
					require.Equal(t, []int{0, 1, 2}, calls)
				} else {
					require.ErrorIs(t, err, failure)
					require.Equal(t, []int{0, 1, 2}[:failAt+1], calls)
				}
			}
		})
	}
}

func TestChainedCallbacksForwardsNotifications(t *testing.T) {
	tests := []struct {
		name string
		call func(ChainedCallbacks)
	}{
		{"stream-closed", func(c ChainedCallbacks) { c.OnStreamClosed(1, &core.Node{}) }},
		{"stream-response", func(c ChainedCallbacks) {
			c.OnStreamResponse(t.Context(), 1, &discovery.DiscoveryRequest{}, &discovery.DiscoveryResponse{})
		}},
		{"delta-stream-closed", func(c ChainedCallbacks) { c.OnDeltaStreamClosed(1, &core.Node{}) }},
		{"delta-stream-response", func(c ChainedCallbacks) {
			c.OnStreamDeltaResponse(1, &discovery.DeltaDiscoveryRequest{}, &discovery.DeltaDiscoveryResponse{})
		}},
		{"fetch-response", func(c ChainedCallbacks) {
			c.OnFetchResponse(&discovery.DiscoveryRequest{}, &discovery.DiscoveryResponse{})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls []int
			var chain ChainedCallbacks
			for i := range 3 {
				callback := func() { calls = append(calls, i) }
				chain = append(chain, server.CallbackFuncs{
					StreamClosedFunc:        func(int64, *core.Node) { callback() },
					StreamResponseFunc:      func(context.Context, int64, *discovery.DiscoveryRequest, *discovery.DiscoveryResponse) { callback() },
					DeltaStreamClosedFunc:   func(int64, *core.Node) { callback() },
					StreamDeltaResponseFunc: func(int64, *discovery.DeltaDiscoveryRequest, *discovery.DeltaDiscoveryResponse) { callback() },
					FetchResponseFunc:       func(*discovery.DiscoveryRequest, *discovery.DiscoveryResponse) { callback() },
				})
			}
			test.call(chain)
			require.Equal(t, []int{0, 1, 2}, calls)
		})
	}
}
