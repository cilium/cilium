// Copyright 2020 Authors of Hubble
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

package container

import (
	"context"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

// RingReader is a reader for a Ring container.
type RingReader struct {
	ring *Ring
	idx  uint64
	ctx  context.Context
	c    <-chan *v1.Event
}

// NewRingReader creates a new RingReader that starts reading the ring at the
// position given by start.
func NewRingReader(ring *Ring, start uint64) *RingReader {
	return &RingReader{
		ring: ring,
		idx:  start,
		ctx:  nil,
	}
}

// Previous reads the event at the current position and decrement the read
// position. Returns ErrInvalidRead if there are no older entries.
func (r *RingReader) Previous() (*v1.Event, error) {
	// We only expect ErrInvalidRead to be returned when reading backwards,
	// therefore we don't try to handle any errors here.
	e, err := r.ring.read(r.idx)
	if err != nil {
		return nil, err
	}
	r.idx--
	return e, nil
}

// Next reads the event at the current position and increment the read position.
// Returns io.EOF if there are no more entries. May return ErrInvalidRead
// if the writer overtook this RingReader.
func (r *RingReader) Next() (*v1.Event, error) {
	// There are two possible errors returned by read():
	//
	// Reader ahead of writer (io.EOF): We have read past the writer.
	// In this case, we want to return nil and don't bump the index, as we have
	// read all existing values that exist now.
	// Writer ahead of reader (ErrInvalidRead): The writer has already
	// overwritten the values we wanted to read. In this case, we want to
	// propagate the error, as trying to catch up would be very racy.
	e, err := r.ring.read(r.idx)
	if err != nil {
		return nil, err
	}
	r.idx++
	return e, nil
}

// NextFollow reads the event at the current position and increment the read
// position by one. If there are no more event to read, NextFollow blocks
// until the next event is added to the ring or the context is cancelled.
func (r *RingReader) NextFollow(ctx context.Context) *v1.Event {
	// if the context changed between invocations, we also have to restart
	// readFrom, as the old readFrom instance will be using the old context.
	if r.c == nil || r.ctx != ctx {
		r.c = r.ring.readFrom(ctx, r.idx)
		r.ctx = ctx
	}

	select {
	case e, ok := <-r.c:
		if !ok {
			// channel can only be closed by readFrom if ctx is cancelled
			r.c = nil
			r.ctx = nil
			return nil
		}
		// increment idx so that future calls to the ring reader will
		// continue reading from were we stopped.
		r.idx++
		return e
	case <-ctx.Done():
		r.c = nil
		r.ctx = nil
		return nil
	}
}
