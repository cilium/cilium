//go:build !windows

package ringbuf

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

type ringbufEventRing struct {
	prod []byte
	cons []byte
	*ringReader
}

func newRingBufEventRing(mapFD, size int) (*ringbufEventRing, error) {
	cons, err := unix.Mmap(mapFD, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("can't mmap consumer page: %w", err)
	}

	prod, err := unix.Mmap(mapFD, (int64)(os.Getpagesize()), os.Getpagesize()+2*size, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		_ = unix.Munmap(cons)
		return nil, fmt.Errorf("can't mmap data pages: %w", err)
	}

	cons_pos := (*uint64)(unsafe.Pointer(&cons[0]))
	prod_pos := (*uint64)(unsafe.Pointer(&prod[0]))

	ring := &ringbufEventRing{
		prod:       prod,
		cons:       cons,
		ringReader: newRingReader(cons_pos, prod_pos, prod[os.Getpagesize():]),
	}
	runtime.SetFinalizer(ring, (*ringbufEventRing).Close)

	return ring, nil
}

func (ring *ringbufEventRing) Close() {
	runtime.SetFinalizer(ring, nil)

	_ = unix.Munmap(ring.prod)
	_ = unix.Munmap(ring.cons)

	ring.prod = nil
	ring.cons = nil
}

type ringReader struct {
	// These point into mmap'ed memory and must be accessed atomically.
	prod_pos, cons_pos *uint64
	mask               uint64
	ring               []byte
}

func newRingReader(cons_ptr, prod_ptr *uint64, ring []byte) *ringReader {
	return &ringReader{
		prod_pos: prod_ptr,
		cons_pos: cons_ptr,
		// cap is always a power of two
		mask: uint64(cap(ring)/2 - 1),
		ring: ring,
	}
}

// To be able to wrap around data, data pages in ring buffers are mapped twice in
// a single contiguous virtual region.
// Therefore the returned usable size is half the size of the mmaped region.
func (rr *ringReader) size() int {
	return cap(rr.ring) / 2
}

// The amount of data available to read in the ring buffer.
func (rr *ringReader) AvailableBytes() uint64 {
	prod := atomic.LoadUint64(rr.prod_pos)
	cons := atomic.LoadUint64(rr.cons_pos)
	return prod - cons
}

// Read a record from an event ring.
func (rr *ringReader) readRecord(rec *Record) error {
	prod := atomic.LoadUint64(rr.prod_pos)
	cons := atomic.LoadUint64(rr.cons_pos)

	for {
		if remaining := prod - cons; remaining == 0 {
			return errEOR
		} else if remaining < sys.BPF_RINGBUF_HDR_SZ {
			return fmt.Errorf("read record header: %w", io.ErrUnexpectedEOF)
		}

		// read the len field of the header atomically to ensure a happens before
		// relationship with the xchg in the kernel. Without this we may see len
		// without BPF_RINGBUF_BUSY_BIT before the written data is visible.
		// See https://github.com/torvalds/linux/blob/v6.8/kernel/bpf/ringbuf.c#L484
		start := cons & rr.mask
		len := atomic.LoadUint32((*uint32)((unsafe.Pointer)(&rr.ring[start])))
		header := ringbufHeader{Len: len}

		if header.isBusy() {
			// the next sample in the ring is not committed yet so we
			// exit without storing the reader/consumer position
			// and start again from the same position.
			return errBusy
		}

		cons += sys.BPF_RINGBUF_HDR_SZ

		// Data is always padded to 8 byte alignment.
		dataLenAligned := uint64(internal.Align(header.dataLen(), 8))
		if remaining := prod - cons; remaining < dataLenAligned {
			return fmt.Errorf("read sample data: %w", io.ErrUnexpectedEOF)
		}

		start = cons & rr.mask
		cons += dataLenAligned

		if header.isDiscard() {
			// when the record header indicates that the data should be
			// discarded, we skip it by just updating the consumer position
			// to the next record.
			atomic.StoreUint64(rr.cons_pos, cons)
			continue
		}

		if n := header.dataLen(); cap(rec.RawSample) < n {
			rec.RawSample = make([]byte, n)
		} else {
			rec.RawSample = rec.RawSample[:n]
		}

		copy(rec.RawSample, rr.ring[start:])
		rec.Remaining = int(prod - cons)
		atomic.StoreUint64(rr.cons_pos, cons)
		return nil
	}
}
