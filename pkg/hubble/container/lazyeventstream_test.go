// Copyright 2020 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// +build !privileged_tests

package container

import (
	"testing"
	"time"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"

	"github.com/golang/protobuf/ptypes"
	"github.com/stretchr/testify/require"
)

// A lazyEventStream lazily generates unique *v1.Events.
type lazyEventStream struct {
	t      *testing.T
	time0  time.Time
	events []*v1.Event
}

// newLazyEventStream returns a new lazyEventStream.
func newLazyEventStream(t *testing.T) *lazyEventStream {
	return &lazyEventStream{
		t:     t,
		time0: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// at returns the ith event. It panics if the ith event has not been generated
// yet.
func (s *lazyEventStream) at(i int) *v1.Event {
	return s.events[i]
}

// fill fills r with events from s.
func (s *lazyEventStream) fill(b *RingBuffer) {
	for range b.buffer {
		b.Write(s.next())
	}
}

// lastSlice returns the last n events. It panics if fewer than n events have been
// generated.
func (s *lazyEventStream) lastSlice(n int) []*v1.Event {
	return s.events[len(s.events)-n:]
}

// n returns the number of events generated.
func (s *lazyEventStream) n() int {
	return len(s.events)
}

// next generates and returns the next unique *v1.Event.
func (s *lazyEventStream) next() *v1.Event {
	timestamp, err := ptypes.TimestampProto(s.time(len(s.events)))
	require.NoError(s.t, err)
	event := &v1.Event{
		Timestamp: timestamp,
	}
	s.events = append(s.events, event)
	return event
}

// time returns the time of the ith event. i can be negative.
func (s *lazyEventStream) time(i int) time.Time {
	return s.time0.Add(time.Duration(i) * time.Second)
}

// writeN writes the next n events to b.
func (s *lazyEventStream) writeN(b *RingBuffer, n int) {
	for i := 0; i < n; i++ {
		s.writeNext(b)
	}
}

// writeNext generates the next event, writes it to r, and returns it.
func (s *lazyEventStream) writeNext(b *RingBuffer) *v1.Event {
	event := s.next()
	b.Write(event)
	return event
}

// slice returns the slice of events from lo to hi.
func (s *lazyEventStream) slice(lo, hi int) []*v1.Event {
	return s.events[lo:hi]
}
