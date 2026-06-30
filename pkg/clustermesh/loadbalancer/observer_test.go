// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/cilium/stream"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/time"
)

func newTestEndpointSliceObserver() *endpointSliceObserver {
	observer := &endpointSliceObserver{}
	observer.emitFn = func(ev endpointSliceEvent) {
		observer.buf = append(observer.buf, ev)
	}
	return observer
}

func TestObserverBufferedStart(t *testing.T) {
	observer := newTestEndpointSliceObserver()

	// Test to send event before calling Observe
	observer.emit(endpointSliceEvent{clusterID: 1})
	observer.emit(endpointSliceEvent{clusterID: 2})

	ctx, cancel := context.WithCancel(t.Context())

	completed := make(chan error, 1)
	events := stream.ToChannel(ctx, observer, stream.WithBufferSize(4), stream.WithErrorChan(completed))
	observer.emit(endpointSliceEvent{clusterID: 3})
	observer.emit(endpointSliceEvent{clusterID: 4})

	// Test that all events are received before and after Observe
	require.EqualValues(t, 1, (<-events).clusterID)
	require.EqualValues(t, 2, (<-events).clusterID)
	require.EqualValues(t, 3, (<-events).clusterID)
	require.EqualValues(t, 4, (<-events).clusterID)

	cancel()
	require.ErrorIs(t, <-completed, context.Canceled)

	_, ok := <-events
	require.False(t, ok, "Expected events channel to be closed")
	require.Nil(t, observer.buf)
}

func TestObserverShutdownDuringBufferedReplay(t *testing.T) {
	observer := newTestEndpointSliceObserver()

	observer.emit(endpointSliceEvent{clusterID: 1})
	observer.emit(endpointSliceEvent{clusterID: 2})

	ctx, cancel := context.WithCancel(t.Context())

	events := make(chan uint32, 2)
	completed := make(chan error, 1)
	observer.Observe(ctx, func(ev endpointSliceEvent) {
		events <- ev.clusterID
		// Cancel after the first event
		cancel()
	}, func(err error) {
		completed <- err
	})

	require.ErrorIs(t, <-completed, context.Canceled)
	require.EqualValues(t, 1, <-events)
	require.Empty(t, events)
}

// TestObserverSerialization test that the observer enforces strict
// serialization by emitting two concurrent events and ensure the second one
// can only be delivered once after the first one is.
func TestObserverSerialization(t *testing.T) {
	observer := newTestEndpointSliceObserver()

	ctx, cancel := context.WithCancel(t.Context())

	var serializationErr atomic.Bool

	enteredObserve := make(chan struct{}, 2)
	releasedObserve := make(chan struct{}, 2)
	events := make(chan uint32, 2)

	var running atomic.Bool
	completed := make(chan error, 1)
	observer.Observe(ctx, func(ev endpointSliceEvent) {
		if !running.CompareAndSwap(false, true) {
			serializationErr.Store(true)
		}
		defer running.Store(false)

		enteredObserve <- struct{}{}
		events <- ev.clusterID
		<-releasedObserve
	}, func(err error) {
		completed <- err
	})

	go observer.emit(endpointSliceEvent{clusterID: 1})
	// Make sure we are processing the first event before sending the second one
	<-enteredObserve

	go observer.emit(endpointSliceEvent{clusterID: 2})

	// Wait to make sure that the second emit has been called/scheduled while
	// the first event is being blocked.
	// Note that this cannot use testing/synctest, as goroutines blocked on
	// mutex are not considered durably blocked.
	time.Sleep(time.Millisecond * 10)

	close(releasedObserve)
	require.Equal(t, uint32(1), <-events)
	require.Equal(t, uint32(2), <-events)

	cancel()
	require.ErrorIs(t, <-completed, context.Canceled)

	require.False(t, serializationErr.Load(), "Concurrent calls detected")
}
