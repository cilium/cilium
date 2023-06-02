// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eventqueue

import (
	"context"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type EventQueueSuite struct{}

var _ = Suite(&EventQueueSuite{})

func (s *EventQueueSuite) TestNewEventQueue(c *C) {
	q := NewEventQueue()
	c.Assert(q.close, Not(IsNil))
	c.Assert(q.events, Not(IsNil))
	c.Assert(q.drain, Not(IsNil))
	c.Assert(q.name, Equals, "")
	c.Assert(cap(q.events), Equals, 1)
}

func (s *EventQueueSuite) TestNewEventQueueBuffered(c *C) {
	q := NewEventQueueBuffered("foo", 25)
	c.Assert(q.name, Equals, "foo")
	c.Assert(cap(q.events), Equals, 25)
}

func (s *EventQueue) TestNilEventQueueOperations(c *C) {
	var qq *EventQueue
	qq.Stop()
	c.Assert(qq, IsNil)
}

func (s *EventQueueSuite) TestStopWithoutRun(c *C) {
	q := NewEventQueue()
	q.Stop()
}

func (s *EventQueueSuite) TestCloseEventQueueMultipleTimes(c *C) {
	q := NewEventQueue()
	q.Stop()
	// Closing event queue twice should not cause panic.
	q.Stop()
}

func (s *EventQueueSuite) TestDrained(c *C) {
	q := NewEventQueue()
	q.Run()

	// Stopping queue should drain it as well.
	q.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*500)
	defer cancel()

	select {
	case <-q.close:
	case <-ctx.Done():
		c.Log("timed out waiting for queue to be drained")
		c.Fail()
	}
}

func (s *EventQueueSuite) TestNilEvent(c *C) {
	q := NewEventQueue()
	res, err := q.Enqueue(nil)
	c.Assert(res, IsNil)
	c.Assert(err, Not(IsNil))
}

func (s *EventQueueSuite) TestNewEvent(c *C) {
	e := NewEvent(&DummyEvent{})
	c.Assert(e.Metadata, Not(IsNil))
	c.Assert(e.eventResults, Not(IsNil))
	c.Assert(e.cancelled, Not(IsNil))
}

type DummyEvent struct{}

func (d *DummyEvent) Handle(ifc chan interface{}) {
	ifc <- struct{}{}
}

func (s *EventQueueSuite) TestEventCancelAfterQueueClosed(c *C) {
	q := NewEventQueue()
	q.Run()
	ev := NewEvent(&DummyEvent{})
	_, err := q.Enqueue(ev)
	c.Assert(err, IsNil)

	// Event should not have been cancelled since queue was not closed.
	c.Assert(ev.WasCancelled(), Equals, false)
	q.Stop()

	ev = NewEvent(&DummyEvent{})
	_, err = q.Enqueue(ev)
	c.Assert(err, IsNil)
	c.Assert(ev.WasCancelled(), Equals, true)
}

type NewHangEvent struct {
	Channel   chan struct{}
	processed bool
}

func (n *NewHangEvent) Handle(ifc chan interface{}) {
	<-n.Channel
	n.processed = true
	ifc <- struct{}{}
}

func CreateHangEvent() *NewHangEvent {
	return &NewHangEvent{
		Channel: make(chan struct{}),
	}
}

func (s *EventQueueSuite) TestDrain(c *C) {
	q := NewEventQueue()
	q.Run()

	nh1 := CreateHangEvent()
	nh2 := CreateHangEvent()
	nh3 := CreateHangEvent()

	ev := NewEvent(nh1)
	_, err := q.Enqueue(ev)
	c.Assert(err, IsNil)

	ev2 := NewEvent(nh2)
	ev3 := NewEvent(nh3)

	_, err = q.Enqueue(ev2)
	c.Assert(err, IsNil)

	var (
		rcvChan <-chan interface{}
		err2    error
	)

	enq := make(chan struct{})

	go func() {
		rcvChan, err2 = q.Enqueue(ev3)
		c.Assert(err2, IsNil)
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
	c.Assert(ok, Equals, false)
	c.Assert(ev3.WasCancelled(), Equals, true)

	// Event wasn't processed because it was drained. See Handle() for
	// NewHangEvent.
	c.Assert(nh3.processed, Equals, false)
}

func (s *EventQueueSuite) TestEnqueueTwice(c *C) {
	q := NewEventQueue()
	q.Run()

	ev := NewEvent(&DummyEvent{})
	res, err := q.Enqueue(ev)
	c.Assert(err, IsNil)
	select {
	case <-res:
	case <-time.After(5 * time.Second):
		c.Fail()
	}

	res, err = q.Enqueue(ev)
	c.Assert(res, IsNil)
	c.Assert(err, Not(IsNil))

	q.Stop()
	q.WaitToBeDrained()
}

func (s *EventQueueSuite) TestForcefulDraining(c *C) {
	// This will test enqueuing an event when the queue was never run and was
	// stopped and drained. The behavior expected is that the event will
	// successfully be enqueued (channel returned is non-nil & no error), and
	// after the event is stopped and drained, the returned channel will
	// unblock.

	q := NewEventQueue()

	ev := NewEvent(&DummyEvent{})
	res, err := q.Enqueue(ev)
	c.Assert(res, Not(IsNil))
	c.Assert(err, IsNil)

	q.Stop()
	q.WaitToBeDrained()

	select {
	case <-res:
	case <-time.After(5 * time.Second):
		c.Fail()
	}
}
