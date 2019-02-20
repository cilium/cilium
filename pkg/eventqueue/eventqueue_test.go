// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package eventqueue

import (
	"context"
	"testing"
	"time"

	. "gopkg.in/check.v1"
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
	c.Assert(cap(q.events), Equals, 1)
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
	case <-q.IsDrained():
	case <-ctx.Done():
		c.Log("timed out waiting for queue to be drained")
		c.Fail()
	}
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
	q.Enqueue(ev)

	// Event should not have been cancelled since queue was not closed.
	c.Assert(ev.WasCancelled(), Equals, false)
	q.Stop()

	ev = NewEvent(&DummyEvent{})
	q.Enqueue(ev)
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
	q.Enqueue(ev)

	ev2 := NewEvent(nh2)
	ev3 := NewEvent(nh3)

	q.Enqueue(ev2)

	var rcvChan <-chan interface{}

	enq := make(chan struct{})

	go func() {
		rcvChan = q.Enqueue(ev3)
		enq <- struct{}{}
	}()

	close(nh1.Channel)

	// Ensure that the event is enqueued. Because nh2.Channel hasn't been closed
	// We know that the event hasn't been handled yet.
	select {
	case <-enq:
		break
	}

	// Stop queue in goroutine so we don't block on all events being processed
	// (because nh2 nor nh3 haven't had their channels closed yet).
	go q.Stop()

	// Ensure channel has began to drain after stopping.
	select {
	case <-q.drain:
	}

	// Allow nh2 handling to unblock so we can wait for ev3 to be cancelled.
	close(nh2.Channel)

	// Event was drained, so it should have been cancelled.
	select {
	case _, ok := <-rcvChan:
		c.Assert(ok, Equals, false)
		c.Assert(ev3.WasCancelled(), Equals, true)

		// Event wasn't processed because it was drained. See Handle() for
		// NewHangEvent.
		c.Assert(nh3.processed, Equals, false)
	}

}
