// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
)

type waitGroupResourceMutator struct {
	completionCh chan *completion.Completion
	gotWaitGroup atomic.Bool
}

func (m *waitGroupResourceMutator) DeleteEnvoyResources(context.Context, xds.Resources, *completion.WaitGroup) error {
	return nil
}

func (m *waitGroupResourceMutator) UpdateEnvoyResources(ctx context.Context, _ xds.Resources, new xds.Resources, wg *completion.WaitGroup) error {
	if wg == nil {
		return nil
	}
	m.gotWaitGroup.Store(true)
	comp := wg.AddCompletionWithCallback(nil, func(err error) {
		if err != nil {
			return
		}
		for _, cb := range new.PortAllocationCallbacks {
			if cb != nil {
				_ = cb(ctx)
			}
		}
	})
	m.completionCh <- comp
	return nil
}

func listenerWithPort(name string, port uint32) *envoy_config_listener.Listener {
	return &envoy_config_listener.Listener{
		Name: name,
		Address: &envoy_config_core.Address{
			Address: &envoy_config_core.Address_SocketAddress{
				SocketAddress: &envoy_config_core.SocketAddress{
					Address: "127.0.0.1",
					PortSpecifier: &envoy_config_core.SocketAddress_PortValue{
						PortValue: port,
					},
				},
			},
		},
	}
}

func TestUpdateEnvoyResourcesWaitsForDynamicListenerPortACK(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	mutator := &waitGroupResourceMutator{completionCh: make(chan *completion.Completion, 1)}
	ops := &envoyOps{xds: mutator}

	resources := xds.NewResources()
	resources.Listeners["listener1"] = listenerWithPort("listener1", 10000)
	var ackCount atomic.Uint64
	resources.PortAllocationCallbacks["listener1"] = func(context.Context) error {
		ackCount.Add(1)
		return nil
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- ops.updateEnvoyResources(ctx, xds.NewResources(), resources)
	}()

	var comp *completion.Completion
	select {
	case comp = <-mutator.completionCh:
	case <-ctx.Done():
		require.FailNow(t, "timed out waiting for xDS completion registration")
	}
	require.True(t, mutator.gotWaitGroup.Load())
	require.Equal(t, uint64(0), ackCount.Load())

	select {
	case err := <-errCh:
		require.FailNow(t, fmt.Sprintf("update returned before LDS ACK: %v", err))
	default:
	}

	comp.Complete(nil)
	require.NoError(t, <-errCh)
	require.Equal(t, uint64(1), ackCount.Load())
}

func TestUpdateEnvoyResourcesDoesNotWaitWithoutPortAllocationCallbacks(t *testing.T) {
	mutator := &waitGroupResourceMutator{completionCh: make(chan *completion.Completion, 1)}
	ops := &envoyOps{xds: mutator}

	resources := xds.NewResources()
	resources.Listeners["listener1"] = listenerWithPort("listener1", 10000)

	require.NoError(t, ops.updateEnvoyResources(context.Background(), xds.NewResources(), resources))
	require.False(t, mutator.gotWaitGroup.Load())
}
