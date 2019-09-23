package perf

import (
	"io"
	"os"
	"runtime"
	"sync/atomic"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
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
	if err == nil {
		return fd, nil
	}

	switch err {
	case unix.E2BIG:
		return -1, errors.WithMessage(unix.E2BIG, "perf_event_attr size is incorrect,check size field for what the correct size should be")
	case unix.EACCES:
		return -1, errors.WithMessage(unix.EACCES, "insufficient capabilities to create this event")
	case unix.EBADFD:
		return -1, errors.WithMessage(unix.EBADFD, "group_fd is invalid")
	case unix.EBUSY:
		return -1, errors.WithMessage(unix.EBUSY, "another event already has exclusive access to the PMU")
	case unix.EFAULT:
		return -1, errors.WithMessage(unix.EFAULT, "attr points to an invalid address")
	case unix.EINVAL:
		return -1, errors.WithMessage(unix.EINVAL, "the specified event is invalid, most likely because a configuration parameter is invalid (i.e. too high, too low, etc)")
	case unix.EMFILE:
		return -1, errors.WithMessage(unix.EMFILE, "this process has reached its limits for number of open events that it may have")
	case unix.ENODEV:
		return -1, errors.WithMessage(unix.ENODEV, "this processor architecture does not support this event type")
	case unix.ENOENT:
		return -1, errors.WithMessage(unix.ENOENT, "the type setting is not valid")
	case unix.ENOSPC:
		return -1, errors.WithMessage(unix.ENOSPC, "the hardware limit for breakpoints)capacity has been reached")
	case unix.ENOSYS:
		return -1, errors.WithMessage(unix.ENOSYS, "sample type not supported by the hardware")
	case unix.EOPNOTSUPP:
		return -1, errors.WithMessage(unix.EOPNOTSUPP, "this event is not supported by the hardware or requires a feature not supported by the hardware")
	case unix.EOVERFLOW:
		return -1, errors.WithMessage(unix.EOVERFLOW, "sample_max_stack is larger than the kernel support; check \"/proc/sys/kernel/perf_event_max_stack\" for maximum supported size")
	case unix.EPERM:
		return -1, errors.WithMessage(unix.EPERM, "insufficient capability to request exclusive access")
	case unix.ESRCH:
		return -1, errors.WithMessage(unix.ESRCH, "pid does not exist")
	default:
		return -1, err
	}
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
