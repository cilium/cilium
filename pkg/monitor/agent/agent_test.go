// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/monitor/agent/listener"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/monitor/payload"
)

// fakeListener is an in-memory listener.MonitorListener recording every
// payload it receives.
type fakeListener struct {
	mu       lock.Mutex
	payloads []payload.Payload
	closed   bool
}

func (f *fakeListener) Enqueue(pl *payload.Payload) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.payloads = append(f.payloads, *pl)
}

func (f *fakeListener) Version() listener.Version {
	return listener.Version1_2
}

func (f *fakeListener) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
}

func (f *fakeListener) recorded() []payload.Payload {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]payload.Payload(nil), f.payloads...)
}

func (f *fakeListener) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

type testEvent struct {
	Source uint16
	Msg    string
}

// TestSendEventDeliversSameDataToAllListeners verifies that every registered
// listener observes the exact same stream of monitor payloads. This replaces
// the former RuntimeDatapathMonitorTest e2e test "delivers the same
// information to multiple monitors".
func TestSendEventDeliversSameDataToAllListeners(t *testing.T) {
	a := newAgent(t.Context(), hivetest.Logger(t))

	listeners := []*fakeListener{{}, {}, {}}
	for _, l := range listeners {
		a.RegisterNewListener(l)
	}

	events := []testEvent{
		{Source: 1, Msg: "first"},
		{Source: 2, Msg: "second"},
		{Source: 3, Msg: "third"},
	}
	for _, ev := range events {
		require.NoError(t, a.SendEvent(api.MessageTypeDebug, ev))
	}

	reference := listeners[0].recorded()
	require.Len(t, reference, len(events))

	for i, pl := range reference {
		// The first byte of the on-wire payload data encodes the message type.
		require.NotEmpty(t, pl.Data)
		assert.Equal(t, byte(api.MessageTypeDebug), pl.Data[0])
		assert.Equal(t, payload.EventSample, pl.Type)

		// All listeners must observe identical payloads in the same order.
		for j, l := range listeners[1:] {
			got := l.recorded()
			require.Len(t, got, len(events), "listener %d is missing events", j+1)
			assert.Equal(t, pl, got[i], "listener %d diverges at event %d", j+1, i)
		}
	}
}

// TestRemoveListenerStopsDelivery verifies that a removed listener is closed
// and stops receiving events, while remaining listeners are unaffected.
func TestRemoveListenerStopsDelivery(t *testing.T) {
	a := newAgent(t.Context(), hivetest.Logger(t))

	removed, kept := &fakeListener{}, &fakeListener{}
	a.RegisterNewListener(removed)
	a.RegisterNewListener(kept)

	require.NoError(t, a.SendEvent(api.MessageTypeDebug, testEvent{Source: 1, Msg: "before"}))
	require.Len(t, removed.recorded(), 1)
	require.Len(t, kept.recorded(), 1)

	a.RemoveListener(removed)
	assert.True(t, removed.isClosed(), "removed listener must be closed")
	assert.False(t, kept.isClosed())

	require.NoError(t, a.SendEvent(api.MessageTypeDebug, testEvent{Source: 2, Msg: "after"}))
	assert.Len(t, removed.recorded(), 1, "removed listener must not receive new events")
	assert.Len(t, kept.recorded(), 2)
}

// TestRegisterListenerOnStoppedAgent verifies that registering a listener on
// an agent whose context has been cancelled immediately closes the listener.
func TestRegisterListenerOnStoppedAgent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	a := newAgent(ctx, hivetest.Logger(t))
	cancel()

	l := &fakeListener{}
	a.RegisterNewListener(l)
	assert.True(t, l.isClosed())
	assert.Empty(t, l.recorded())
}
