// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eventqueue

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
)

type EventQueueSuite struct{}

func TestNewEventQueue(t *testing.T) {
	logger := hivetest.Logger(t)
	q := NewEventQueue(logger)
	require.NotNil(t, q.close)
	require.NotNil(t, q.events)
	require.NotNil(t, q.drain)
	require.Empty(t, q.name)
	require.Equal(t, 1, cap(q.events))
}

func TestNewEventQueueBuffered(t *testing.T) {
	logger := hivetest.Logger(t)
	q := NewEventQueueBuffered(logger, "foo", 25)
	require.Equal(t, "foo", q.name)
	require.Equal(t, 25, cap(q.events))
}

func TestNilEventQueueOperations(t *testing.T) {
	var qq *EventQueue
	qq.Stop()
	require.Nil(t, qq)
}

func TestStopWithoutRun(t *testing.T) {
	logger := hivetest.Logger(t)
	q := NewEventQueue(logger)
	q.Stop()
}

func TestCloseEventQueueMultipleTimes(t *testing.T) {
	logger := hivetest.Logger(t)
	q := NewEventQueue(logger)
	q.Stop()
	// Closing event queue twice should not cause panic.
	q.Stop()
}

func TestDrained(t *testing.T) {
	logger := hivetest.Logger(t)
	q := NewEventQueue(logger)
	q.Run()

	// Stopping queue should drain it as well.
	q.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*500)
	defer cancel()

	select {
	case <-q.close:
	case <-ctx.Done():
		t.Log("timed out waiting for queue to be drained")
		t.Fail()
	}
}

func TestNilEvent(t *testing.T) {
	logger := hivetest.Logger(t)
	q := NewEventQueue(logger)
	res, err := q.Enqueue(nil)
	require.Nil(t, res)
	require.Error(t, err)
}

func TestNewEvent(t *testing.T) {
	e := NewEvent(&DummyEvent{})
	require.NotNil(t, e.Metadata)
	require.NotNil(t, e.eventResults)
	require.NotNil(t, e.cancelled)
}

type DummyEvent struct{}

func (d *DummyEvent) Handle(ifc chan any) {
	ifc <- struct{}{}
}

func TestEventCancelAfterQueueClosed(t *testing.T) {
	logger := hivetest.Logger(t)
	q := NewEventQueue(logger)
	q.Run()
	ev := NewEvent(&DummyEvent{})
	_, err := q.Enqueue(ev)
	require.NoError(t, err)

	// Event should not have been cancelled since queue was not closed.
	require.False(t, ev.WasCancelled())
	q.Stop()

	ev = NewEvent(&DummyEvent{})
	_, err = q.Enqueue(ev)
	require.NoError(t, err)
	require.True(t, ev.WasCancelled())
}

type NewHangEvent struct {
	Channel   chan struct{}
	processed bool
}

func (n *NewHangEvent) Handle(ifc chan any) {
	<-n.Channel
	n.processed = true
	ifc <- struct{}{}
}

func CreateHangEvent() *NewHangEvent {
	return &NewHangEvent{
		Channel: make(chan struct{}),
	}
}

func TestDrain(t *testing.T) {
	logger := hivetest.Logger(t)
	q := NewEventQueue(logger)
	q.Run()

	nh1 := CreateHangEvent()
	nh2 := CreateHangEvent()
	nh3 := CreateHangEvent()

	ev := NewEvent(nh1)
	_, err := q.Enqueue(ev)
	require.NoError(t, err)

	ev2 := NewEvent(nh2)
	ev3 := NewEvent(nh3)

	_, err = q.Enqueue(ev2)
	require.NoError(t, err)

	var (
		rcvChan <-chan any
		err2    error
	)

	enq := make(chan struct{})

	go func() {
		rcvChan, err2 = q.Enqueue(ev3)
		require.NoError(t, err2)
		enq <- struct{}{}
	}()

	close(nh1.Channel)

	// Ensure that the event is enqueued. Because nh2.Channel hasn't been closed
	// We know that the event hasn't been handled yet.
	<-enq

	// Stop queue in goroutine so we don't block on all events being processed
	// (because nh2 nor nh3 haven't had their channels closed yet).
	go q.Stop()

	// Ensure channel has began to drain after stopping.
	<-q.drain

	// Allow nh2 handling to unblock so we can wait for ev3 to be cancelled.
	close(nh2.Channel)

	// Event was drained, so it should have been cancelled.
	_, ok := <-rcvChan
	require.False(t, ok)
	require.True(t, ev3.WasCancelled())

	// Event wasn't processed because it was drained. See Handle() for
	// NewHangEvent.
	require.False(t, nh3.processed)
}

func TestEnqueueTwice(t *testing.T) {
	logger := hivetest.Logger(t)
	q := NewEventQueue(logger)
	q.Run()

	ev := NewEvent(&DummyEvent{})
	res, err := q.Enqueue(ev)
	require.NoError(t, err)
	select {
	case <-res:
	case <-time.After(5 * time.Second):
		t.Fail()
	}

	res, err = q.Enqueue(ev)
	require.Nil(t, res)
	require.Error(t, err)

	q.Stop()
	q.WaitToBeDrained()
}

func TestForcefulDraining(t *testing.T) {
	// This will test enqueuing an event when the queue was never run and was
	// stopped and drained. The behavior expected is that the event will
	// successfully be enqueued (channel returned is non-nil & no error), and
	// after the event is stopped and drained, the returned channel will
	// unblock.

	logger := hivetest.Logger(t)
	q := NewEventQueue(logger)

	ev := NewEvent(&DummyEvent{})
	res, err := q.Enqueue(ev)
	require.NotNil(t, res)
	require.NoError(t, err)

	q.Stop()
	q.WaitToBeDrained()

	select {
	case <-res:
	case <-time.After(5 * time.Second):
		t.Fail()
	}
}
