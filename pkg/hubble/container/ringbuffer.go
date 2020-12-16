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

package container

import (
	"time"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/lock"
)

// A RingBuffer buffers a fixed number of recent events and fans them out to
// multiple readers. Writing events never blocks, but readers may not see all
// events if they are too slow.
//
// A ring buffer can be empty, in which case it operates as a fan out to
// multiple readers.
//
// Written events are given sequence numbers in the order in which they are
// received.
type RingBuffer struct {
	// mu synchronizes access. It is included as an unexported field rather than
	// embedded struct so that its methods are not exported.
	mu lock.RWMutex

	// tail is the sequence number of the oldest event in the buffer.
	tail int

	// head is the sequence number of the next event.
	head int

	buffer  []*v1.Event
	readers map[chan<- *v1.Event]*ReaderStats

	// sent is the total number of events sent to followers.
	sent int

	// dropped is the total number of events dropped by followers.
	dropped int

	// rUnlockLockFunc is called between releasing a read lock and acquiring a
	// write lock. It is for testing purposes only.
	rUnlockLockFunc func()
}

// A ReaderCancelFunc cancels a reader and returns its statistics.
type ReaderCancelFunc func() ReaderStats

// A RingBufferOption sets an option on a RingBuffer.
type RingBufferOption func(*RingBuffer)

// A ReaderStats collects statistics on a reader.
type ReaderStats struct {
	Sent    int
	Dropped int
}

// A RingBufferStatus contains a snapshot of a ring buffer's state.
type RingBufferStatus struct {
	NumEvents       int
	SeenEvents      int
	OldestEventTime time.Time
	NewestEventTime time.Time
}

// WithCapacity sets the capacity.
func WithCapacity(capacity int) RingBufferOption {
	return func(b *RingBuffer) {
		b.buffer = make([]*v1.Event, capacity)
	}
}

// NewRingBuffer returns a new RingBuffer with the given options.
func NewRingBuffer(options ...RingBufferOption) *RingBuffer {
	b := &RingBuffer{
		readers: make(map[chan<- *v1.Event]*ReaderStats),
	}
	for _, o := range options {
		o(b)
	}
	return b
}

// Buffer copies of all the events in r's buffer at the moment of the function
// call into events. If events is nil or its capacity is less than the size of a
// buffer then a new slice is allocated. The returned slice can be re-used in
// later calls to Buffer.
func (b *RingBuffer) Buffer(events []*v1.Event) []*v1.Event {
	if b.zeroCapacity() {
		return events[:0]
	}

	b.mu.RLock()
	if b.tail == b.head {
		b.mu.RUnlock()
		return nil
	}
	if cap(events) < len(b.buffer) {
		events = make([]*v1.Event, b.head-b.tail, len(b.buffer))
	} else if len(events) < b.head-b.tail {
		events = append(events, make([]*v1.Event, b.head-b.tail-len(events))...)
	}
	headIndex := b.head % len(b.buffer)
	tailIndex := b.tail % len(b.buffer)
	if headIndex > tailIndex {
		copy(events, b.buffer[tailIndex:headIndex])
	} else {
		copy(events[0:len(b.buffer)-headIndex], b.buffer[tailIndex:len(b.buffer)])
		copy(events[len(b.buffer)-headIndex:], b.buffer[0:headIndex])
	}
	b.mu.RUnlock()
	return events
}

// ReadAll returns a channel that returns all events in b and then switches to
// follow mode and a cancellation function.
func (b *RingBuffer) ReadAll(capacity int) (<-chan *v1.Event, ReaderCancelFunc) {
	if b.zeroCapacity() {
		return b.ReadNew(capacity)
	}

	b.mu.RLock()
	seq := b.tail
	b.mu.RUnlock()
	return b.ReadFrom(seq, capacity)
}

// ReadBackward returns a channel that returns all events in b starting from the
// head and going backward in time, the head at the moment ReadBackward was
// called, and a cancellation function. The returned head can be used in a call
// to ReadFrom to read forward.
func (b *RingBuffer) ReadBackward(capacity int) (<-chan *v1.Event, int, ReaderCancelFunc) {
	ch := make(chan *v1.Event, capacity)

	// Acquire a read lock.
	b.mu.RLock()
	head := b.head

	// If the buffer is empty then we are done.
	if head == b.tail {
		b.mu.RUnlock()
		close(ch)
		return ch, head, func() ReaderStats {
			return ReaderStats{}
		}
	}

	// Copy the head event from the buffer so that it cannot be overwritten.
	seq := head - 1
	event := b.buffer[seq%len(b.buffer)]

	// Release the read lock.
	b.mu.RUnlock()

	// Start a goroutine to send events from the ring buffer to the channel.
	// Once all events in the ring buffer have been sent, close the channel.
	cancelCh := make(chan struct{})
	resultCh := make(chan ReaderStats)
	go func() {
		var readerStats ReaderStats
		defer func() {
			resultCh <- readerStats
			close(resultCh)
		}()

		defer close(ch)

		for {
			select {
			case <-cancelCh:
				return
			case ch <- event:
				readerStats.Sent++
				seq--

				// Acquire a read lock.
				b.mu.RLock()

				// If we have reached the tail then we are done.
				if seq < b.tail {
					b.mu.RUnlock()
					return
				}

				// Copy the next event from the ring buffer so that it cannot be
				// overwritten.
				event = b.buffer[seq%len(b.buffer)]

				// Release the read lock.
				b.mu.RUnlock()
			}
		}
	}()

	return ch, head, func() ReaderStats {
		close(cancelCh)
		return <-resultCh
	}
}

// ReadCurrent returns a channel that returns all events in b and a cancellation
// function.
func (b *RingBuffer) ReadCurrent(capacity int) (<-chan *v1.Event, ReaderCancelFunc) {
	ch := make(chan *v1.Event, capacity)

	// If there is no buffer then we are done.
	if b.zeroCapacity() {
		close(ch)
		return ch, func() ReaderStats {
			return ReaderStats{}
		}
	}

	// Acquire a read lock. Note that if we start a goroutine to read events
	// then this lock is released in the goroutine.
	b.mu.RLock()

	// Record the sequence numbers of the current events in the buffer.
	seq := b.tail
	last := b.head

	// If the buffer is empty then we are done.
	if seq == last {
		b.mu.RUnlock()
		close(ch)
		return ch, func() ReaderStats {
			return ReaderStats{}
		}
	}

	// Copy the first event from the buffer so that it cannot be overwritten.
	event := b.buffer[seq%len(b.buffer)]

	// Start a goroutine to send events from the ring buffer to the channel.
	// Once all events in the ring buffer have been sent, close the channel.
	cancelCh := make(chan struct{})
	resultCh := make(chan ReaderStats)
	go func() {
		var readerStats ReaderStats
		defer func() {
			resultCh <- readerStats
			close(resultCh)
		}()

		defer close(ch)

		// Release the read lock that was acquired in the parent goroutine.
		b.mu.RUnlock()

		for {
			// Send the event to the reader or wait for cancellation.
			select {
			case <-cancelCh:
				return
			case ch <- event:
				readerStats.Sent++
				seq++

				// If we have caught up to the last event then we are done.
				if seq >= last {
					return
				}

				// Acquire a read lock.
				b.mu.RLock()

				// If the reader was slow then we might have dropped events from
				// the ring buffer. Record the number of dropped events and
				// advance to the oldest event in the ring buffer.
				if seq < b.tail {
					// If the last event we want is no longer in the ring buffer
					// then we are done.
					if last < b.tail {
						b.mu.RUnlock()
						readerStats.Dropped += last - seq
						return
					}
					// Otherwise record the number of dropped events and advance
					// to the last event in the ring buffer.
					readerStats.Dropped += b.tail - seq
					seq = b.tail
				}

				// Copy the next event from the ring buffer so that it cannot be
				// overwritten.
				event = b.buffer[seq%len(b.buffer)]

				// Release the read lock.
				b.mu.RUnlock()
			}
		}
	}()

	return ch, func() ReaderStats {
		close(cancelCh)
		return <-resultCh
	}
}

// ReadFrom returns a channel with the given capacity that returns events from r
// from seq onwards and a cancellation function.
func (b *RingBuffer) ReadFrom(seq, capacity int) (<-chan *v1.Event, ReaderCancelFunc) {
	ch := make(chan *v1.Event, capacity)

	// Start a goroutine to send events from the ring buffer to the channel.
	// Once all events in the ring buffer have been sent, switch to follow mode.
	readerReadyCh := make(chan struct{})
	doneCh := make(chan struct{})
	resultCh := make(chan ReaderStats)
	go func() {
		var readerStats ReaderStats
		defer close(resultCh)

		for {
			// Take a read lock.
			b.mu.RLock()

			// Signal that the reader is ready after taking the read lock for
			// the first time.
			if readerReadyCh != nil {
				close(readerReadyCh)
				readerReadyCh = nil
			}

			// If we have caught up with the most recent event then switch to
			// follow mode.
			if seq == b.head {
				// Release the read lock and acquire the write lock.
				b.mu.RUnlock()
				// FIXME find a way to eliminate this comparison in non-test
				// code
				if b.rUnlockLockFunc != nil {
					b.rUnlockLockFunc()
				}
				b.mu.Lock()
				// Retry the test in case the state changed while the mutex was
				// unlocked.
				if seq == b.head {
					// Add the reader (i.e. switch to follow mode) and terminate
					// this goroutine.
					b.readers[ch] = &readerStats
					b.mu.Unlock()
					return
				}
				// Otherwise, release the write lock and re-acquire a read lock.
				b.mu.Unlock()
				b.mu.RLock()
			}

			// If the reader was slow then we might have dropped events from the
			// ring buffer. Record the number of dropped events and advance to
			// the oldest event in the ring buffer.
			if seq < b.tail {
				readerStats.Dropped += b.tail - seq
				seq = b.tail
			}

			// Copy the next event from the ring buffer so that it cannot be
			// overwritten.
			event := b.buffer[seq%len(b.buffer)]

			// Release the read lock.
			b.mu.RUnlock()

			// Send the event to the reader or wait for cancellation.
			select {
			case <-doneCh:
				resultCh <- readerStats
				return
			case ch <- event:
				readerStats.Sent++
				seq++
			}
		}
	}()

	// Wait for the reader to be ready. This ensures that the reader goroutine
	// has started and that the reader has had the opportunity to read at an
	// event from the buffer.
	<-readerReadyCh

	return ch, func() ReaderStats {
		// Stop the goroutine if it is still running.
		close(doneCh)

		// Stop the follower if we have switched to follow mode.
		b.mu.Lock()
		readerStats, ok := b.readers[ch]
		if ok {
			delete(b.readers, ch)
		}
		b.mu.Unlock()

		// If we were in follow mode then return the stats.
		if ok {
			return *readerStats
		}

		// Otherwise return the stats from the goroutine.
		return <-resultCh
	}
}

// ReadNew returns a channel with the given capacity that sends events written
// to b and a cancellation function. capacity should be zero (unbuffered) except
// in special circumstances (testing). Events will be dropped if the reader of
// the returned channel cannot keep up.
//
// FIXME how to make capacity only available to test code?
func (b *RingBuffer) ReadNew(capacity int) (<-chan *v1.Event, ReaderCancelFunc) {
	ch := make(chan *v1.Event, capacity)
	b.mu.Lock()
	b.readers[ch] = &ReaderStats{}
	b.mu.Unlock()

	return ch, func() ReaderStats {
		b.mu.Lock()
		readerStats := *b.readers[ch]
		delete(b.readers, ch)
		b.mu.Unlock()
		close(ch)
		return readerStats
	}
}

// ReadSince returns a channel with capacity that returns all events since t and
// a cancellation function. t is assumed to be in the past. If t is more recent
// than the last event in the buffer then all new events are returned.
func (b *RingBuffer) ReadSince(t time.Time, capacity int) (<-chan *v1.Event, ReaderCancelFunc) {
	if b.zeroCapacity() {
		return b.ReadNew(capacity)
	}

	b.mu.RLock()
	// If there are events in the buffer then scan backwards to find the first
	// event before t and then return events after that event.
	// FIXME replace this linear search with binary search
	// FIXME can improve search by assuming that events are roughly evenly distributed
	for seq := b.head - 1; seq >= b.tail; seq-- {
		et := eventTime(b.buffer[seq%len(b.buffer)])
		if !et.IsZero() && et.Before(t) {
			b.mu.RUnlock()
			return b.ReadFrom(seq+1, capacity)
		}
	}
	b.mu.RUnlock()
	return b.ReadFrom(0, capacity)
}

// Status returns the status of b.
func (b *RingBuffer) Status() RingBufferStatus {
	b.mu.RLock()
	s := RingBufferStatus{
		NumEvents:  b.head - b.tail,
		SeenEvents: b.head,
	}
	for i := b.tail; i < b.head; i++ {
		if t := eventTime(b.buffer[i%len(b.buffer)]); !t.IsZero() {
			s.OldestEventTime = t
			break
		}
	}
	for i := b.head - 1; i >= b.tail; i-- {
		if t := eventTime(b.buffer[i%len(b.buffer)]); !t.IsZero() {
			s.NewestEventTime = t
			break
		}
	}
	b.mu.RUnlock()
	return s
}

// Write writes event to r.
func (b *RingBuffer) Write(event *v1.Event) {
	b.mu.Lock()
	if len(b.buffer) > 0 {
		b.buffer[b.head%len(b.buffer)] = event
	}
	b.head++
	if b.tail < b.head-len(b.buffer) {
		b.tail = b.head - len(b.buffer)
	}
	for ch, readerStats := range b.readers {
		select {
		case ch <- event:
			b.sent++
			readerStats.Sent++
		default:
			b.dropped++
			readerStats.Dropped++
		}
	}
	b.mu.Unlock()
}

// zeroCapacity returns true if b has zero capacity.
func (b *RingBuffer) zeroCapacity() bool {
	// len(b.buffer) does not change after initialization so we do not need to
	// take a read lock.
	return len(b.buffer) == 0
}

// eventTime returns the time of event.
func eventTime(event *v1.Event) time.Time {
	// FIXME verify this
	// FIXME do we need tp extract different times from different events?
	return event.Timestamp.AsTime()
}

// min returns the minimum of a and b.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
