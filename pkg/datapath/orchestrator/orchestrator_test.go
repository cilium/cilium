// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/promise"
)

type hostEndpointWaitPromise struct {
	promise.Promise[*endpoint.Endpoint]
	entered chan struct{}
	once    sync.Once
}

func (p *hostEndpointWaitPromise) Await(ctx context.Context) (*endpoint.Endpoint, error) {
	p.once.Do(func() { close(p.entered) })
	return p.Promise.Await(ctx)
}

func TestWaitForHostEndpointBeforeInitialization(t *testing.T) {
	const (
		templateHostEndpointID = uint64(0xffff)
		realHostEndpointID     = uint64(1234)
	)

	originalHostEndpointID, _ := node.GetEndpointID()
	t.Cleanup(func() {
		node.SetEndpointID(originalHostEndpointID)
	})
	node.SetEndpointID(templateHostEndpointID)

	resolver, ready := promise.New[*endpoint.Endpoint]()
	hostEndpoint := &hostEndpointWaitPromise{
		Promise: ready,
		entered: make(chan struct{}),
	}
	orchestrator := &orchestrator{
		params: orchestratorParams{HostEndpointPromise: hostEndpoint},
	}

	var initialized atomic.Bool
	var initializedWithID atomic.Uint64
	done := make(chan error, 1)
	go func() {
		err := orchestrator.waitForHostEndpoint(context.Background())
		if err == nil {
			id, _ := node.GetEndpointID()
			initializedWithID.Store(id)
			initialized.Store(true)
		}
		done <- err
	}()

	<-hostEndpoint.entered
	require.False(t, initialized.Load())

	node.SetEndpointID(realHostEndpointID)
	resolver.Resolve(&endpoint.Endpoint{})

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("host endpoint wait did not finish")
	}
	require.True(t, initialized.Load())
	require.Equal(t, realHostEndpointID, initializedWithID.Load())
}

func TestWaitForHostEndpointCancellation(t *testing.T) {
	_, ready := promise.New[*endpoint.Endpoint]()
	hostEndpoint := &hostEndpointWaitPromise{
		Promise: ready,
		entered: make(chan struct{}),
	}
	orchestrator := &orchestrator{
		params: orchestratorParams{HostEndpointPromise: hostEndpoint},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- orchestrator.waitForHostEndpoint(ctx)
	}()

	<-hostEndpoint.entered
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}
