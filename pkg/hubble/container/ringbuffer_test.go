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

// FIXME add test for Write during RUnlock/Lock in AllEvents

package container

import (
	"fmt"
	"sync"
	"testing"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"

	"github.com/stretchr/testify/assert"
)

// testCapacities is a slice of capacities used for testing.
var testCapacities = []int{
	0,    // For empty ring buffers.
	1,    // For edge cases.
	4,    // For debugging small powers of two.
	7,    // For debugging small powers of two minus one.
	255,  // A power of two minus one.
	4096, // A larger power of two.
}

func TestNewRingBuffer(t *testing.T) {
	forEachCapacity(t, testCapacities, nil, func(t *testing.T, capacity int, b *RingBuffer) {
		assert.Equal(t, capacity, len(b.buffer))
		assert.Zero(t, b.tail)
		assert.Zero(t, b.head)
		assert.Empty(t, b.Buffer(nil))
		assert.Equal(t, RingBufferStatus{}, b.Status())
	})
}

func TestRingBufferReadAll(t *testing.T) {
	forEachCapacity(t, testCapacities, nil, func(t *testing.T, capacity int, b *RingBuffer) {
		// This test requires a non-zero capacity.
		if capacity == 0 {
			return
		}

		events := newLazyEventStream(t)
		events.fill(b)

		// Request all events. Create a buffered channel so the events can be
		// received without blocking.
		ch, cancel := b.ReadAll(3 * capacity)

		// Test that the first events received are the buffered events.
		for i := 0; i < capacity; i++ {
			assert.Equal(t, events.at(i), <-ch)
		}

		// Write the remaining events.
		for i := capacity; i < 3*capacity; i++ {
			events.writeNext(b)
		}

		// Test that the events received match all events.
		for i := capacity; i < 3*capacity; i++ {
			assert.Equal(t, events.at(i), <-ch)
		}
		requireChannelEmpty(t, ch)

		// Check reader statistics.
		readerStats := cancel()
		assert.Equal(t, events.n(), readerStats.Sent)
		assert.Zero(t, readerStats.Dropped)

		// Test that no events are received after calling cancel.
		events.writeNext(b)
		requireChannelEmpty(t, ch)

		// Check status.
		assert.Equal(t, expectedStatus(events, capacity), b.Status())
		assert.Equal(t, 2*capacity, b.sent, "sent")
		assert.Equal(t, 0, b.dropped, "dropped")
	})
}

func TestRingBufferReadAllCancel(t *testing.T) {
	t.Skip("broken test") // FIXME
	forEachCapacity(t, testCapacities, nil, func(t *testing.T, capacity int, b *RingBuffer) {
		// This test requires a capacity of at least a few events.
		if capacity < 4 {
			return
		}

		events := newLazyEventStream(t)
		events.fill(b)

		// Create a reader that we'll cancel while receiving the buffered
		// events.
		ch1, cancel1 := b.ReadAll(capacity / 2)

		// Create a reader that we'll cancel immediately after switching to follow
		// mode.
		ch2, cancel2 := b.ReadAll(capacity)

		// Create a reader that we'll cancel some time after switching to follow
		// mode.
		ch3, cancel3 := b.ReadAll(capacity + 1)

		// Read the first half of the buffered events.
		for i := 0; i < capacity/2; i++ {
			assert.Equal(t, events.at(i), <-ch1)
			assert.Equal(t, events.at(i), <-ch2)
			assert.Equal(t, events.at(i), <-ch3)
		}

		// Cancel reader 1 and test that it no longer receives events.
		readerStats1 := cancel1()
		assert.Equal(t, capacity/2, readerStats1.Sent)
		assert.Zero(t, readerStats1.Dropped)
		requireChannelEmpty(t, ch1)

		// Read the second half of the buffered events.
		for i := capacity / 2; i < capacity; i++ {
			assert.Equal(t, events.at(i), <-ch2)
			assert.Equal(t, events.at(i), <-ch3)
		}

		readerStats2 := cancel2()
		assert.Equal(t, capacity, readerStats2.Sent)
		assert.Zero(t, readerStats2.Dropped)
		// requireChannelEmpty(t, ch2)

		readerStats3 := cancel3()
		assert.Equal(t, capacity, readerStats3.Sent)
		assert.Zero(t, readerStats3.Dropped)
		// requireChannelEmpty(t, ch3)
	})
}

func TestRingBufferReadAllSlowReader(t *testing.T) {
	forEachCapacity(t, testCapacities, nil, func(t *testing.T, capacity int, b *RingBuffer) {
		events := newLazyEventStream(t)
		events.fill(b)

		// Request all events. Create a buffered channel so the events can be
		// received without blocking.
		ch, cancel := b.ReadAll(1)

		// Test that the first events received are the buffered events.
		for i := 0; i < capacity; i++ {
			assert.Equal(t, events.at(i), <-ch)
		}

		// Test a slow reader than only reads one event for every two written.
		for i := capacity; i < 3*capacity; i += 2 {
			events.writeNext(b)
			events.writeNext(b)
			<-ch
		}

		// Check reader statistics.
		readerStats := cancel()
		assert.Equal(t, 2*capacity, readerStats.Sent)
		assert.Equal(t, capacity, readerStats.Dropped)

		// Check status.
		assert.Equal(t, expectedStatus(events, capacity), b.Status())
	})
}

func TestRingBufferReadBackward(t *testing.T) {
	for _, percentFull := range []int{0, 50, 100, 150, 200} {
		t.Run(fmt.Sprintf("percent_full_%d", percentFull), func(t *testing.T) {
			forEachCapacity(t, testCapacities, nil, func(t *testing.T, capacity int, b *RingBuffer) {
				events := newLazyEventStream(t)
				n := capacity * percentFull / 100
				events.writeN(b, n)

				ch, head, cancel := b.ReadBackward(capacity)
				assert.Equal(t, events.n(), head)
				expectedEvents := min(capacity, n)
				for i := 0; i < expectedEvents; i++ {
					assert.Equal(t, events.at(n-i-1), <-ch)
				}
				requireChannelEmpty(t, ch)

				readerStats := cancel()
				assert.Equal(t, expectedEvents, readerStats.Sent)
				assert.Zero(t, readerStats.Dropped)
			})
		})
	}
}

func TestRingBufferReadBackwardSlowReader(t *testing.T) {
	forEachCapacity(t, testCapacities, nil, func(t *testing.T, capacity int, b *RingBuffer) {
		events := newLazyEventStream(t)
		events.fill(b)

		ch, head, cancel := b.ReadBackward(0)
		assert.Equal(t, events.n(), head)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Read the first half of the events.
			for i := 0; i < capacity/2; i++ {
				assert.Equal(t, events.at(capacity-i-1), <-ch)
			}

			// Fill the buffer again so that the tail catches up.
			events.fill(b)

			// Test that there is at most one event left.
			expectedSent := capacity / 2
			if capacity > 0 {
				select {
				case event := <-ch:
					assert.Equal(t, events.at(capacity-capacity/2-1), event)
					expectedSent++
				default:
				}
			}
			requireChannelEmpty(t, ch)

			readerStats := cancel()
			assert.Equal(t, expectedSent, readerStats.Sent)
			assert.Zero(t, readerStats.Dropped)
		}()
		wg.Wait()
	})
}
func TestRingBufferReadCurrent(t *testing.T) {
	for _, percentFull := range []int{0, 50, 100, 150, 200} {
		t.Run(fmt.Sprintf("percent_full_%d", percentFull), func(t *testing.T) {
			forEachCapacity(t, testCapacities, nil, func(t *testing.T, capacity int, b *RingBuffer) {
				events := newLazyEventStream(t)
				n := capacity * percentFull / 100
				events.writeN(b, n)

				ch, cancel := b.ReadCurrent(capacity)
				expectedEvents := min(capacity, n)
				for i := 0; i < expectedEvents; i++ {
					assert.Equal(t, events.at(n-expectedEvents+i), <-ch)
				}
				requireChannelEmpty(t, ch)

				readerStats := cancel()
				assert.Equal(t, expectedEvents, readerStats.Sent)
				assert.Zero(t, readerStats.Dropped)
				requireChannelEmpty(t, ch)
			})
		})
	}
}

func TestRingBufferReadCurrentCancel(t *testing.T) {
	forEachCapacity(t, testCapacities, nil, func(t *testing.T, capacity int, b *RingBuffer) {
		// This test requires a capacity of at least two.
		if capacity < 2 {
			return
		}

		events := newLazyEventStream(t)
		events.fill(b)

		ch, cancel := b.ReadCurrent(0)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Read the first half of the events.
			for i := 0; i < capacity/2; i++ {
				assert.Equal(t, events.at(i), <-ch)
			}

			// Cancel reading.
			readerStats := cancel()
			assert.Equal(t, capacity/2, readerStats.Sent)
			assert.Zero(t, readerStats.Dropped)

			requireChannelEmpty(t, ch)
		}()
		wg.Wait()
	})
}

func TestRingBufferReadCurrentZeroCapacity(t *testing.T) {
	b := NewRingBuffer()
	ch, cancel := b.ReadCurrent(0)
	requireChannelEmpty(t, ch)
	readerStats := cancel()
	assert.Zero(t, readerStats.Sent)
	assert.Zero(t, readerStats.Dropped)
}

func TestRingBufferReadAllVerySlowReader(t *testing.T) {
	forEachCapacity(t, testCapacities, nil, func(t *testing.T, capacity int, b *RingBuffer) {
		// This test requires a non-zero capacity.
		if capacity == 0 {
			return
		}

		events := newLazyEventStream(t)
		events.fill(b)

		// Request all events. Create a buffered channel so the events can be
		// received without blocking.
		ch, cancel := b.ReadAll(1)

		// Test that the first events received are the buffered events.
		for i := 0; i < capacity; i++ {
			<-ch
		}

		// Fill the buffer again, twice, without receiving events.
		for i := 0; i < 2*capacity; i++ {
			events.writeNext(b)
		}

		<-ch
		// assert.Equal(t, events.at(2*capacity-1), <-ch) // FIXME
		// FIXME complete this test

		cancel()
	})
}

func TestRingBufferReadNewCancel(t *testing.T) {
	forEachCapacity(t, testCapacities, nil, func(t *testing.T, capacity int, b *RingBuffer) {
		events := newLazyEventStream(t)
		events.fill(b)

		// Create a buffered channel that can receive one event without blocking.
		ch, cancel := b.ReadNew(1)

		// Test that an event is received.
		event1 := events.writeNext(b)
		assert.Equal(t, event1, requireChannelReceive(t, ch))

		// Test that events that cannot be received are dropped.
		event2 := events.writeNext(b)
		event3 := events.writeNext(b)
		assert.Contains(t, []*v1.Event{event2, event3}, requireChannelReceive(t, ch))

		// Test that no events are received after calling cancel.
		readerStats := cancel()
		assert.Equal(t, 2, readerStats.Sent)
		assert.Equal(t, 1, readerStats.Dropped)
		events.writeNext(b)
		requireChannelEmpty(t, ch)

		// Check status.
		assert.Equal(t, expectedStatus(events, capacity), b.Status())
		assert.Equal(t, 2, b.sent, "sent")
		assert.Equal(t, 1, b.dropped, "dropped")
	})
}

func TestRingBufferReadSince(t *testing.T) {
	forEachCapacity(t, testCapacities, nil, func(t *testing.T, capacity int, b *RingBuffer) {
		// This test requires a capacity greater than one.
		if capacity <= 1 {
			return
		}

		for _, tc := range []struct {
			name           string
			sinceIndex     int
			expectedEvents int
		}{
			{
				name:           "before_last",
				sinceIndex:     -1,
				expectedEvents: 2 * capacity,
			},
			{
				name:           "last",
				sinceIndex:     0,
				expectedEvents: 2 * capacity,
			},
			{
				name:           "second",
				sinceIndex:     2,
				expectedEvents: 2*capacity - 2,
			},
			{
				name:           "next",
				sinceIndex:     capacity,
				expectedEvents: capacity,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				b := NewRingBuffer(WithCapacity(capacity))
				events := newLazyEventStream(t)
				events.fill(b)

				// Create a reader that reads the ith event onwards.
				ch, cancel := b.ReadSince(events.time(tc.sinceIndex), 2*capacity)

				// Fill the buffer a second time.
				events.fill(b)

				// Count the number of events received.
				eventsReceived := 0
				for i := 0; i < tc.expectedEvents; i++ {
					select {
					case <-ch:
						eventsReceived++
					default:
						t.Fatalf("%d events received, expected %d", eventsReceived, tc.expectedEvents)
					}
				}
				cancel()
				requireChannelEmpty(t, ch)
				assert.Equal(t, tc.expectedEvents, eventsReceived)
			})
		}
	})
}

func TestRingBufferReadSinceZeroCapacity(t *testing.T) {
	b := NewRingBuffer()
	events := newLazyEventStream(t)
	b.Write(events.next())
	ch, cancel := b.ReadSince(events.time(0), 1)
	event := events.writeNext(b)
	assert.Equal(t, event, <-ch)
	requireChannelEmpty(t, ch)
	cancel()
}

func TestRingBufferWrite(t *testing.T) {
	forEachCapacity(t, testCapacities, nil, func(t *testing.T, capacity int, b *RingBuffer) {
		// Skip the test if the capacity is too large. This test is accidentally
		// quadratic in the buffer's capacity, i.e. the running time is
		// O(capacity^2), because it calls Buffer() (which is O(capacity))
		// O(capacity) times.
		if capacity > 1024 {
			return
		}

		events := newLazyEventStream(t)
		var buffer []*v1.Event

		// Fill the the buffer with unique events.
		for i := 0; i < capacity; i++ {
			events.writeNext(b)
			assert.Equal(t, i+1, b.head-b.tail)
			buffer = b.Buffer(buffer)
			assert.Equal(t, events.slice(0, i+1), buffer)
		}

		// Write more events to fill the buffer twice.
		for i := capacity; i < 3*capacity; i++ {
			events.writeNext(b)
			assert.Equal(t, capacity, b.head-b.tail)
			buffer = b.Buffer(buffer)
			assert.Equal(t, events.lastSlice(capacity), buffer)
		}
	})
}

// expectedStatus returns the expected RingBufferStatus after all the events
// from events have been written to a ring buffer with the given capacity.
func expectedStatus(events *lazyEventStream, capacity int) RingBufferStatus {
	s := RingBufferStatus{
		NumEvents:  min(events.n(), capacity),
		SeenEvents: events.n(),
	}
	if capacity > 0 {
		s.OldestEventTime = events.time(events.n() - capacity)
		s.NewestEventTime = events.time(events.n() - 1)
	}
	return s
}

// forEachCapacity calls f with a new RingBuffer for each capacity.
func forEachCapacity(t *testing.T, capacities []int, options []RingBufferOption, f func(*testing.T, int, *RingBuffer)) {
	for _, capacity := range capacities {
		t.Run(fmt.Sprintf("capacity_%d", capacity), func(t *testing.T) {
			os := []RingBufferOption{
				WithCapacity(capacity),
			}
			os = append(os, options...)
			b := NewRingBuffer(os...)
			f(t, capacity, b)
		})
	}
}

// requireChannelEmpty requires that there are no more events available to read
// from ch.
func requireChannelEmpty(t *testing.T, ch <-chan *v1.Event) {
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("unexpected receive")
		}
	default:
	}
}

// requireChannelReceive requires that an event can be read from ch.
func requireChannelReceive(t *testing.T, ch <-chan *v1.Event) *v1.Event {
	select {
	case event := <-ch:
		return event
	default:
		t.Fatal("no event received")
		return nil
	}
}

// withRUnlockLockFunc sets the function that is called between releasing the
// read lock and acquiring the write lock when switching a reader into follow
// mode.
func withRUnlockLockFunc(f func()) RingBufferOption {
	return func(b *RingBuffer) {
		b.rUnlockLockFunc = f
	}
}
