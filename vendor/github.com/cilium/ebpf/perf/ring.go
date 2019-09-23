package perf

import (
	"io"
	"os"
	"runtime"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf/internal/unix"

	"github.com/pkg/errors"
)

// perfEventRing is a page of metadata followed by
// a variable number of pages which form a ring buffer.
type perfEventRing struct {
	fd   int
	cpu  int
	mmap []byte
	*ringReader
}

func newPerfEventRing(cpu, perCPUBuffer, watermark int) (*perfEventRing, error) {
	if watermark >= perCPUBuffer {
		return nil, errors.Errorf("watermark must be smaller than perCPUBuffer")
	}

	// Round to nearest page boundary and allocate
	// an extra page for meta data
	pageSize := os.Getpagesize()
	nPages := (perCPUBuffer + pageSize - 1) / pageSize
	size := (1 + nPages) * pageSize

	fd, err := createPerfEvent(cpu, watermark)
	if err != nil {
		return nil, errors.Wrap(err, "can't create perf event")
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}

	mmap, err := unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	// This relies on the fact that we allocate an extra metadata page,
	// and that the struct is smaller than an OS page.
	// This use of unsafe.Pointer isn't explicitly sanctioned by the
	// documentation, since a byte is smaller than sampledPerfEvent.
	meta := (*unix.PerfEventMmapPage)(unsafe.Pointer(&mmap[0]))

	ring := &perfEventRing{
		fd:         fd,
		cpu:        cpu,
		mmap:       mmap,
		ringReader: newRingReader(meta, mmap[meta.Data_offset:meta.Data_offset+meta.Data_size]),
	}
	runtime.SetFinalizer(ring, (*perfEventRing).Close)

	return ring, nil
}

func (ring *perfEventRing) Close() {
	runtime.SetFinalizer(ring, nil)
	unix.Close(ring.fd)
	unix.Munmap(ring.mmap)

	ring.fd = -1
	ring.mmap = nil
}

func createPerfEvent(cpu, watermark int) (int, error) {
	if watermark == 0 {
		watermark = 1
	}

	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_SOFTWARE,
		Config:      unix.PERF_COUNT_SW_BPF_OUTPUT,
		Bits:        unix.PerfBitWatermark,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Wakeup:      uint32(watermark),
	}

	attr.Size = uint32(unsafe.Sizeof(attr))
	fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	return fd, errors.Wrap(err, "can't create perf event")
}

type ringReader struct {
	meta       *unix.PerfEventMmapPage
	head, tail uint64
	mask       uint64
	ring       []byte
}

func newRingReader(meta *unix.PerfEventMmapPage, ring []byte) *ringReader {
	return &ringReader{
		meta: meta,
		head: atomic.LoadUint64(&meta.Data_head),
		tail: atomic.LoadUint64(&meta.Data_tail),
		// cap is always a power of two
		mask: uint64(cap(ring) - 1),
		ring: ring,
	}
}

func (rr *ringReader) loadHead() {
	rr.head = atomic.LoadUint64(&rr.meta.Data_head)
}

func (rr *ringReader) writeTail() {
	// Commit the new tail. This lets the kernel know that
	// the ring buffer has been consumed.
	atomic.StoreUint64(&rr.meta.Data_tail, rr.tail)
}

func (rr *ringReader) Read(p []byte) (int, error) {
	start := int(rr.tail & rr.mask)

	n := len(p)
	// Truncate if the read wraps in the ring buffer
	if remainder := cap(rr.ring) - start; n > remainder {
		n = remainder
	}

	// Truncate if there isn't enough data
	if remainder := int(rr.head - rr.tail); n > remainder {
		n = remainder
	}

	copy(p, rr.ring[start:start+n])
	rr.tail += uint64(n)

	if rr.tail == rr.head {
		return n, io.EOF
	}

	return n, nil
}
