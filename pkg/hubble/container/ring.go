// Copyright 2019-2020 Authors of Hubble
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
	"sync/atomic"
	"unsafe"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/math"
	"github.com/cilium/cilium/pkg/lock"
)

// Ring is a ring buffer that stores *v1.Event
type Ring struct {
	// mask to calculate the index to write into 'data'.
	mask uint64
	// write is the last position used to write into the 'data'. This
	// field ANDed with 'mask' gives the index position of 'data' to be written.
	write uint64
	// cycleExp is the exponent of 2^x of 'dataLen'. Since 'mask' is always
	// 'dataLen'-1 and 'dataLen' is always 2^x we can calculate the writing
	// cycle by doing 'write' / '2^cycleExp', or since we want better performance we
	// can also do 'write' >> 'cycleExp'.
	cycleExp uint8
	// cycleMask is the mask used to calculate the correct cycle of a position.
	cycleMask uint64
	// dataLen is the length of the internal buffer.
	dataLen uint64
	// data is the internal buffer of this ring buffer.
	data []*v1.Event
	// notify{Mu,Ch} are used to signal a waiting reader in readFrom when the
	// writer has written a new value.
	// We cannot use sync.Cond as it cannot be used in select statements.
	notifyMu lock.Mutex
	notifyCh chan struct{}
}

// NewRing creates a ring buffer. For efficiency, the internal
// buffer length will be a bitmask of ones + 1. The most significant bit
// position of this bitmask will be same position of the most significant bit
// position of 'n'.
// E.g.:
//  NewRing(254) -> internal buffer length: 256
//  NewRing(255) -> internal buffer length: 256
//  NewRing(256) -> internal buffer length: 512
func NewRing(n int) *Ring {
	msb := math.MSB(uint64(n))
	if msb == 64 {
		// we don't want to overflow dataLen below
		return nil
	}
	l := math.GetMask(msb)
	dataLen := uint64(l + 1)
	cycleExp := uint8(math.MSB(l+1)) - 1
	return &Ring{
		mask:      l,
		cycleExp:  cycleExp,
		cycleMask: ^uint64(0) >> cycleExp,
		dataLen:   dataLen,
		data:      make([]*v1.Event, dataLen, dataLen),
		notifyMu:  lock.Mutex{},
		notifyCh:  nil,
	}
}

// dataLoadAtomic performs an atomic load on `r.data[dataIdx]`.
// `dataIdx` is the array index with the cycle counter already masked out.
// This ensures that the point load/store itself is data race free. However,
// it is the callers responsibility to ensure that the read is semantically
// correct, i.e. by checking that the read cycle is ahead of the write cycle.
func (r *Ring) dataLoadAtomic(dataIdx uint64) (e *v1.Event) {
	slot := unsafe.Pointer(&r.data[dataIdx])
	return (*v1.Event)(atomic.LoadPointer((*unsafe.Pointer)(slot)))
}

// dataLoadAtomic performs an atomic store as `r.data[dataIdx] = e`.
// `dataIdx` is the array index with the cycle counter already masked out.
// This ensures that the point load/store itself is a data race.
func (r *Ring) dataStoreAtomic(dataIdx uint64, e *v1.Event) {
	slot := unsafe.Pointer(&r.data[dataIdx])
	atomic.StorePointer((*unsafe.Pointer)(slot), unsafe.Pointer(e))
}

// Len returns the number of elements in the ring buffer, similar to builtin `len()`.
func (r *Ring) Len() uint64 {
	write := atomic.LoadUint64(&r.write)
	if write >= r.dataLen {
		return r.dataLen
	}
	return write
}

// Cap returns the total capacity of the ring buffer, similar to builtin `cap()`.
func (r *Ring) Cap() uint64 {
	return r.dataLen
}

// Write writes the given event into the ring buffer in the next available
// writing block. The entry must not be nil, otherwise readFrom will block when
// reading back this event.
func (r *Ring) Write(entry *v1.Event) {
	// We need to lock the notification mutex when updating r.write, otherwise
	// there is a race condition where a readFrom goroutine goes to sleep
	// after we sent out the notification.
	// This lock is only shared with other readFrom instances that are about
	// to go to sleep, so contention should be low. Notably, readers which are
	// far away from the current write pointer will still be able to make
	// progress concurrently.

	r.notifyMu.Lock()

	write := atomic.AddUint64(&r.write, 1)
	writeIdx := (write - 1) & r.mask
	r.dataStoreAtomic(writeIdx, entry)

	// notify any sleeping readers
	if r.notifyCh != nil {
		close(r.notifyCh)
		r.notifyCh = nil
	}

	r.notifyMu.Unlock()
}

// LastWriteParallel returns the last element written.
func (r *Ring) LastWriteParallel() uint64 {
	// We can't possible know when the r.write - 1 element was written
	// since we increment r.write first and only afterwards we write into the
	// internal buffer. We can be 100% sure that the element, as long
	// Write(*v1.Event) calls are serialized, that the r.write - 2 was
	// written.
	return atomic.LoadUint64(&r.write) - 2
}

// LastWrite returns the last element written.
// Note: If Write(*v1.Event) is being executed concurrently with Read(uint64)
// please use LastWriteParallel instead.
func (r *Ring) LastWrite() uint64 {
	return atomic.LoadUint64(&r.write) - 1
}

// read reads the *v1.Event from the given read position. Returns false if
// that position is no longer available to be read, returns true otherwise.
func (r *Ring) read(read uint64) (*v1.Event, bool) {
	readIdx := read & r.mask
	event := r.dataLoadAtomic(readIdx)

	lastWrite := atomic.LoadUint64(&r.write) - 1
	lastWriteIdx := lastWrite & r.mask

	// for simplicity, assume that 'cycle', 'write' and 'index' are uint8
	// and the ring has mask = 0x3 (7). This means there will be a total of 8
	// slots to be written in the ring buffer and a total of 32 cycles.
	// As writing is performed in parallel, the way we check if the read is
	// valid is by checking if the read was performed withing a 'valid cycle'.
	// For example, if the last write was at index 3 cycle 0, it means we can
	// read since index 2 cycle 0 all the way back to index 4 cycle 31 (0x1f).
	// We can't read index 3 cycle 0 because we might not have written into it
	// yet, or we might have, we simply can't be sure.
	//
	//                     +---valid read-+  +position possibly being written
	//                     |              |  |  +next position to be written (r.write)
	//                     V              V  V  V
	// write: f8 f9 fa fb fc fd fe ff  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
	// index:  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
	// cycle: 1f 1f 1f 1f 1f 1f 1f 1f  0  0  0  0  0  0  0  0  1  1  1  1  1  1  1  1
	readCycle := read >> r.cycleExp
	writeCycle := lastWrite >> r.cycleExp
	if (readCycle == writeCycle && readIdx < lastWriteIdx) ||
		(readCycle == (writeCycle-1)&r.cycleMask && readIdx > lastWriteIdx) {
		return event, true
	}
	return nil, false
}

// readFrom continues to read from the given position until the context is
// cancelled.
func (r *Ring) readFrom(ctx context.Context, read uint64) <-chan *v1.Event {
	// TODO should we create the channel or the caller?
	const returnedBufferChLen = 1000
	ch := make(chan *v1.Event, returnedBufferChLen)
	go func() {
		// halfCycle is the middle of a cycle.
		// a half cycle is (^uint64(0)/r.dataLen)/2
		// which translates into (^uint64(0)>>r.dataLen)>>1
		halfCycle := (^uint64(0) >> r.cycleExp) >> 1
		defer func() {
			close(ch)
		}()

		// read forever until ctx is done
		for ; ; read++ {
			readIdx := read & r.mask
			event := r.dataLoadAtomic(readIdx)

			lastWrite := atomic.LoadUint64(&r.write) - 1
			lastWriteIdx := lastWrite & r.mask
			writeCycle := lastWrite >> r.cycleExp
			readCycle := read >> r.cycleExp
			switch {
			// This case is where X is marked
			//                        +----------------valid read------------+  +position possibly being written
			//                        |                                      |  |  +next position to be written (r.write)
			//                        V     X                                V  V  V
			// write: f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
			// index:  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
			// cycle: 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
			case event != nil && readCycle == (writeCycle-1)&r.cycleMask && readIdx > lastWriteIdx:
				select {
				case ch <- event:
					continue
				case <-ctx.Done():
					return
				}
			// This case is where X is marked
			//                        +----------------valid read------------+  +position possibly being written
			//                        |                                      |  |  +next position to be written (r.write)
			//                        V                                   X  V  V  V
			// write: f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
			// index:  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
			// cycle: 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
			case event != nil && readCycle == writeCycle:
				if readIdx < lastWriteIdx {
					select {
					case ch <- event:
						continue
					case <-ctx.Done():
						return
					}
				}
				// If we are in the same cycle as the writer and we are in this
				// branch it means the reader caught the writer so it needs to
				// wait until a new event is received by the writer.
				fallthrough

			// This is a ring buffer, we will stop the reader, i.e. we will
			// read the same index over and over until the writer reached
			// the reader, if the readCycle is >= writeCycle + 1 *and*
			// readCycle < writeCycle + half of a cycle.
			// half of a cycle is used to know if the reader is behind or a head
			// of the writer.
			// This case is where X is marked
			//                        +----------------valid read------------+  +position possibly being written
			//                        |                                      |  |  +next position to be written (r.write)
			//                        V                                      V  V  V                          X
			// write: f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
			// index:  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
			// cycle: 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
			case event == nil || readCycle >= (writeCycle+1)&r.cycleMask && readCycle < (halfCycle+writeCycle)&r.cycleMask:
				// The writer has already written a new event so there's no
				// need to stop the reader.

				// Before going to sleep, we need to check that there has been
				// no write in the meantime. This check can only be race free
				// if the lock on notifyMu is held, otherwise a write can occur
				// before we obtain the notifyCh instance.
				r.notifyMu.Lock()
				if lastWrite != atomic.LoadUint64(&r.write)-1 {
					// A write has occurred - retry
					r.notifyMu.Unlock()
					read--
					continue
				}

				// This channel will be closed by the writer if it makes a write
				if r.notifyCh == nil {
					r.notifyCh = make(chan struct{})
				}
				notifyCh := r.notifyCh
				r.notifyMu.Unlock()

				// Sleep until a write occurs or the context is cancelled
				select {
				case <-notifyCh:
					read--
					continue
				case <-ctx.Done():
					return
				}

			}
		}
	}()
	return ch
}
