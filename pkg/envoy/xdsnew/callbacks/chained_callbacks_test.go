// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"errors"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	envoy_server "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/stretchr/testify/require"
)

func TestChainedCallbacksForwardsDeltaCallbacks(t *testing.T) {
	var calls []string
	newCallbacks := func(name string) envoy_server.CallbackFuncs {
		return envoy_server.CallbackFuncs{
			DeltaStreamOpenFunc: func(context.Context, int64, string) error {
				calls = append(calls, name+"-open")
				return nil
			},
			StreamDeltaRequestFunc: func(int64, *discovery.DeltaDiscoveryRequest) error {
				calls = append(calls, name+"-request")
				return nil
			},
			StreamDeltaResponseFunc: func(int64, *discovery.DeltaDiscoveryRequest, *discovery.DeltaDiscoveryResponse) {
				calls = append(calls, name+"-response")
			},
			DeltaStreamClosedFunc: func(int64, *core.Node) {
				calls = append(calls, name+"-close")
			},
		}
	}

	callbacks := ChainedCallbacks{newCallbacks("first"), newCallbacks("second")}
	require.NoError(t, callbacks.OnDeltaStreamOpen(context.Background(), 1, ""))
	require.NoError(t, callbacks.OnStreamDeltaRequest(1, &discovery.DeltaDiscoveryRequest{}))
	callbacks.OnStreamDeltaResponse(1, &discovery.DeltaDiscoveryRequest{}, &discovery.DeltaDiscoveryResponse{})
	callbacks.OnDeltaStreamClosed(1, &core.Node{})

	require.Equal(t, []string{
		"first-open", "second-open",
		"first-request", "second-request",
		"first-response", "second-response",
		"first-close", "second-close",
	}, calls)
}

func TestChainedCallbacksReturnsFirstError(t *testing.T) {
	expectedErr := errors.New("stop callbacks")
	secondCalled := false
	callbacks := ChainedCallbacks{
		envoy_server.CallbackFuncs{
			StreamDeltaRequestFunc: func(int64, *discovery.DeltaDiscoveryRequest) error {
				return expectedErr
			},
		},
		envoy_server.CallbackFuncs{
			StreamDeltaRequestFunc: func(int64, *discovery.DeltaDiscoveryRequest) error {
				secondCalled = true
				return nil
			},
		},
	}

	require.ErrorIs(t, callbacks.OnStreamDeltaRequest(1, &discovery.DeltaDiscoveryRequest{}), expectedErr)
	require.False(t, secondCalled)
}
