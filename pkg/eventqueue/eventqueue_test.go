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
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/testutils"
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
	c.Assert(q.drained, Not(IsNil))
	c.Assert(cap(q.events), Equals, 1)
}

func (s *EventQueueSuite) TestCloseEventQueueMultipleTimes(c *C) {
	q := NewEventQueue()
	q.Stop()
	// Closing event queue twice should not cause panic.
	q.Stop()
}

func (s *EventQueueSuite) TestNewEvent(c *C) {
	e := NewEvent(struct{}{})
	c.Assert(e.Metadata, Not(IsNil))
	c.Assert(e.EventResults, Not(IsNil))
	c.Assert(e.Cancelled, Not(IsNil))
}

type DummyEvent struct{}

func (d *DummyEvent) Handle() interface{} {
	return struct{}{}
}

type LongDummyEvent struct{}

func (l *LongDummyEvent) Handle() interface{} {
	time.Sleep(2 * time.Second)
	return struct{}{}
}

func (s *EventQueueSuite) TestEventCancelAfterQueueClosed(c *C) {
	q := NewEventQueue()
	go q.Run()
	ev := NewEvent(&DummyEvent{})
	q.Enqueue(ev)

	// Event should not have been cancelled since queue was not closed.
	c.Assert(ev.WasCancelled(), Equals, false)
	q.Stop()

	ev = NewEvent(&DummyEvent{})
	q.Enqueue(ev)
	c.Assert(ev.WasCancelled(), Equals, true)
}

func (s *EventQueueSuite) TestCancelWhenQueued(c *C) {
	q := NewEventQueue()
	go q.Run()
	ev := NewEvent(&LongDummyEvent{})
	ev2 := NewEvent(&LongDummyEvent{})
	// This event is guaranteed to be taken off the queue because the close
	// channel hasn't been closed yet.
	q.Enqueue(ev)

	// Queue another event in the background. This event *will* be cancelled
	// because we are closing the close channel for it has a chance to be consumed.
	go q.Enqueue(ev2)
	q.Stop()

	// CHeck that EventResults channel is closed.
	c.Assert(testutils.WaitUntil(func() bool {
		select {
		case <-ev.EventResults:
			return true
		default:
			return false
		}
	}, 5*time.Second), IsNil)

	select {
	case <-ev.EventResults:
	default:

	}

	// Wait for queue to be drained.
	c.Assert(testutils.WaitUntil(func() bool {
		select {
		case <-q.drained:
			return true
		default:
			return false
		}
	}, 10*time.Second), IsNil)

	// If the queue is drained, the events channel should be closed too.
	c.Assert(testutils.WaitUntil(func() bool {
		select {
		case <-q.events:
			return true
		default:
			return false
		}
	}, 10*time.Second), IsNil)

	// Event should be cancelled since it was not running before the queue was
	// stopped.
	c.Assert(ev2.WasCancelled(), Equals, true)
}
