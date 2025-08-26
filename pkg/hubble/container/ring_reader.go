// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package container

import (
	"context"
	"sync"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/lock"
)

// RingReader is a reader for a Ring container.
type RingReader struct {
	ring          *Ring
	idx           uint64
	ctx           context.Context
	mutex         lock.Mutex // protects writes to followChan
	followChan    chan *v1.Event
	followChanLen int
	wg            sync.WaitGroup
}

// NewRingReader creates a new RingReader that starts reading the ring at the
// position given by start.
func NewRingReader(ring *Ring, start uint64) *RingReader {
	return newRingReader(ring, start, 1000)
}

func newRingReader(ring *Ring, start uint64, bufferLen int) *RingReader {
	return &RingReader{
		ring:          ring,
		idx:           start,
		ctx:           nil,
		followChanLen: bufferLen,
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
	if r.ctx != ctx {
		r.mutex.Lock()
		if r.followChan == nil {
			r.followChan = make(chan *v1.Event, r.followChanLen)
		}
		r.mutex.Unlock()

		r.wg.Add(1)
		go func(ctx context.Context) {
			r.ring.readFrom(ctx, r.idx, r.followChan)
			r.mutex.Lock()
			if ctx.Err() != nil && r.followChan != nil { // context is done
				close(r.followChan)
				r.followChan = nil
			}
			r.mutex.Unlock()
			r.wg.Done()
		}(ctx)
		r.ctx = ctx
	}
	defer func() {
		if ctx.Err() != nil { // context is done
			r.ctx = nil
		}
	}()

	r.mutex.Lock()
	followChan := r.followChan
	r.mutex.Unlock()

	select {
	case e, ok := <-followChan:
		if !ok {
			// the channel is closed so the context is done
			return nil
		}
		// increment idx so that future calls to the ring reader will
		// continue reading from were we stopped.
		r.idx++
		return e
	case <-ctx.Done():
		return nil
	}
}

// Close waits for any spawned goroutines to finish. It is not
// required to call Close on a RingReader but it may be useful for specific
// situations such as testing. Must not be called concurrently with NextFollow,
// as otherwise NextFollow spawns new goroutines that are not waited on.
func (r *RingReader) Close() error {
	r.wg.Wait()
	return nil
}
