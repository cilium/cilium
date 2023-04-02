// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package container

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/math"
	"github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/lock"
)

// Capacity is the interface that wraps Cap.
type Capacity interface {
	// Cap returns the actual capacity.
	Cap() capacity
	// AsInt returns the actual capacity as an int.
	AsInt() int
}

// capacity implements Capacity.
type capacity uint16

// Cap returns the actual capacity.
func (c capacity) Cap() capacity {
	return c
}

// AsInt returns the actual capacity as an int.
func (c capacity) AsInt() int {
	return int(c)
}

// CapacityN represent possible buffer capacities for Ring where N is the
// actual capacity.
const (
	Capacity1 capacity = 1<<(iota+1) - 1
	Capacity3
	Capacity7
	Capacity15
	Capacity31
	Capacity63
	Capacity127
	Capacity255
	Capacity511
	Capacity1023
	Capacity2047
	Capacity4095
	Capacity8191
	Capacity16383
	Capacity32767
	Capacity65535
)

// NewCapacity creates a new Capacity from n.
// The value of n MUST satisfy n=2^i -1 for i = [1, 16]; ie:
//
//	1, 3, 7, ..., 2047, 4095, ..., 65535
//
// Constants CapacityN represent all possible values of n and are valid
// Capacity that can be provided to NewRing.
func NewCapacity(n int) (Capacity, error) {
	switch {
	case n > int(^capacity(0)):
		return nil, fmt.Errorf("invalid capacity: too large: %d", n)
	case n > 0:
		if n&(n+1) == 0 {
			return capacity(n), nil
		}
	}
	return nil, fmt.Errorf("invalid capacity: must be one less than an integer power of two: %d", n)
}

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
	// halfCycle is half the total number of cycles
	halfCycle uint64
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

// NewRing creates a ring buffer where n specifies the capacity.
func NewRing(n Capacity) *Ring {
	// n.Cap() should already be a mask of one's but let's ensure it is
	mask := math.GetMask(math.MSB(uint64(n.Cap())))
	dataLen := uint64(mask + 1) // one unreadable slot is reserved writing
	cycleExp := uint8(math.MSB(mask+1)) - 1
	// half cycle is (^uint64(0)/dataLen)/2 == (^uint64(0)>>cycleExp)>>1
	halfCycle := (^uint64(0) >> cycleExp) >> 1

	return &Ring{
		mask:      mask,
		cycleExp:  cycleExp,
		cycleMask: ^uint64(0) >> cycleExp,
		halfCycle: halfCycle,
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
		return r.Cap()
	}
	return write
}

// Cap returns the total capacity of the ring buffer, similar to builtin `cap()`.
func (r *Ring) Cap() uint64 {
	return r.dataLen - 1 // one slot is reserved for writing and never readable
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

// OldestWrite returns the oldest element written.
// Note: It should only be used to read from the beginning of the buffer.
func (r *Ring) OldestWrite() uint64 {
	write := atomic.LoadUint64(&r.write)
	if write > r.dataLen {
		return write - r.dataLen
	}
	return 0
}

func getLostEvent() *v1.Event {
	metrics.LostEvents.WithLabelValues(strings.ToLower(flowpb.LostEventSource_HUBBLE_RING_BUFFER.String())).Inc()
	now := time.Now().UTC()
	return &v1.Event{
		Timestamp: &timestamppb.Timestamp{
			Seconds: now.Unix(),
			Nanos:   int32(now.Nanosecond()),
		},
		Event: &flowpb.LostEvent{
			Source:        flowpb.LostEventSource_HUBBLE_RING_BUFFER,
			NumEventsLost: 1,
			Cpu:           nil,
		},
	}
}

// read the *v1.Event from the given read position. Returns an error if
// the position is not valid. A position is invalid either because it has
// already been overwritten by the writer (in which case ErrInvalidRead is
// returned) or because the position is ahead of the writer (in which case
// io.EOF is returned).
func (r *Ring) read(read uint64) (*v1.Event, error) {
	readIdx := read & r.mask
	event := r.dataLoadAtomic(readIdx)

	lastWrite := atomic.LoadUint64(&r.write) - 1
	lastWriteIdx := lastWrite & r.mask

	// for simplicity, assume that 'cycle', 'write' and 'index' are uint8
	// and the ring has mask = 0x3 (7). This means there will be a total of 8
	// slots to be written in the ring buffer and a total of 32 cycles.
	// As writing is performed in parallel, the way we check if the read is
	// valid is by checking if the read was performed within a 'valid cycle'.
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

	prevWriteCycle := (writeCycle - 1) & r.cycleMask
	maxWriteCycle := (writeCycle + r.halfCycle) & r.cycleMask

	switch {
	// Case: Reader in current cycle and accessing valid indices
	case readCycle == writeCycle && readIdx < lastWriteIdx:
		if event == nil {
			// This case should never happen, as the writer must never write
			// a nil value. In case it happens anyway, we just stop reading.
			return nil, io.EOF
		}
		return event, nil
	// Case: Reader in previous cycle and accessing valid indices
	case readCycle == prevWriteCycle && readIdx > lastWriteIdx:
		if event == nil {
			// If the ring buffer is not yet fully populated, we treat nil
			// as a value which is about to be overwritten
			return getLostEvent(), nil
		}
		return event, nil
	// Case: Reader ahead of writer
	case readCycle >= writeCycle && readCycle < maxWriteCycle:
		return nil, io.EOF
	// Case: Reader behind writer
	default:
		return getLostEvent(), nil
	}
}

// readFrom continues to read from the given position until the context is
// cancelled. This function does not return until the context is done.
func (r *Ring) readFrom(ctx context.Context, read uint64, ch chan<- *v1.Event) {
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
		case event == nil || readCycle >= (writeCycle+1)&r.cycleMask && readCycle < (r.halfCycle+writeCycle)&r.cycleMask:
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
		default:
			// The writer overwrote the entry before we had time to read it.
			// Send a ListEvent to notify the read-miss.
			select {
			case ch <- getLostEvent():
				continue
			case <-ctx.Done():
				return
			}
		}
	}
}
