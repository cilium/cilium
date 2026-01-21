//go:build !windows

package ringbuf

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/epoll"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

var (
	ErrClosed  = os.ErrClosed
	ErrFlushed = epoll.ErrFlushed
	errEOR     = errors.New("end of ring")
	errBusy    = errors.New("sample not committed yet")
)

// ringbufHeader from 'struct bpf_ringbuf_hdr' in kernel/bpf/ringbuf.c
type ringbufHeader struct {
	Len uint32
	_   uint32 // pg_off, only used by kernel internals
}

const ringbufHeaderSize = int(unsafe.Sizeof(ringbufHeader{}))

func (rh *ringbufHeader) isBusy() bool {
	return rh.Len&sys.BPF_RINGBUF_BUSY_BIT != 0
}

func (rh *ringbufHeader) isDiscard() bool {
	return rh.Len&sys.BPF_RINGBUF_DISCARD_BIT != 0
}

func (rh *ringbufHeader) dataLen() int {
	return int(rh.Len & ^uint32(sys.BPF_RINGBUF_BUSY_BIT|sys.BPF_RINGBUF_DISCARD_BIT))
}

type Record struct {
	RawSample []byte

	// The minimum number of bytes remaining in the ring buffer after this Record has been read.
	Remaining int
}

// Reader allows reading bpf_ringbuf_output
// from user space.
type Reader struct {
	poller *epoll.Poller

	// mu protects read/write access to the Reader structure
	mu          sync.Mutex
	ring        *ringbufEventRing
	epollEvents []unix.EpollEvent
	haveData    bool
	deadline    time.Time
	bufferSize  int
	pendingErr  error
}

// NewReader creates a new BPF ringbuf reader.
func NewReader(ringbufMap *ebpf.Map) (*Reader, error) {
	if ringbufMap.Type() != ebpf.RingBuf {
		return nil, fmt.Errorf("invalid Map type: %s", ringbufMap.Type())
	}

	maxEntries := int(ringbufMap.MaxEntries())
	if maxEntries == 0 || (maxEntries&(maxEntries-1)) != 0 {
		return nil, fmt.Errorf("ringbuffer map size %d is zero or not a power of two", maxEntries)
	}

	poller, err := epoll.New()
	if err != nil {
		return nil, err
	}

	if err := poller.Add(ringbufMap.FD(), 0); err != nil {
		poller.Close()
		return nil, err
	}

	ring, err := newRingBufEventRing(ringbufMap.FD(), maxEntries)
	if err != nil {
		poller.Close()
		return nil, fmt.Errorf("failed to create ringbuf ring: %w", err)
	}

	return &Reader{
		poller:      poller,
		ring:        ring,
		epollEvents: make([]unix.EpollEvent, 1),
		bufferSize:  ring.size(),
	}, nil
}

// Close frees resources used by the reader.
//
// It interrupts calls to Read.
func (r *Reader) Close() error {
	if err := r.poller.Close(); err != nil {
		if errors.Is(err, os.ErrClosed) {
			return nil
		}
		return err
	}

	// Acquire the lock. This ensures that Read isn't running.
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.ring != nil {
		r.ring.Close()
		r.ring = nil
	}

	return nil
}

// SetDeadline controls how long Read and ReadInto will block waiting for samples.
//
// Passing a zero time.Time will remove the deadline.
func (r *Reader) SetDeadline(t time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.deadline = t
}

// Read the next record from the BPF ringbuf.
//
// Calling [Close] interrupts the method with [os.ErrClosed]. Calling [Flush]
// makes it return all records currently in the ring buffer, followed by [ErrFlushed].
//
// Returns [os.ErrDeadlineExceeded] if a deadline was set and after all records
// have been read from the ring.
//
// See [ReadInto] for a more efficient version of this method.
func (r *Reader) Read() (Record, error) {
	var rec Record
	return rec, r.ReadInto(&rec)
}

// ReadInto is like Read except that it allows reusing Record and associated buffers.
func (r *Reader) ReadInto(rec *Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.ring == nil {
		return fmt.Errorf("ringbuffer: %w", ErrClosed)
	}

	for {
		if !r.haveData {
			if pe := r.pendingErr; pe != nil {
				r.pendingErr = nil
				return pe
			}

			_, err := r.poller.Wait(r.epollEvents[:cap(r.epollEvents)], r.deadline)
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ErrFlushed) {
				// Ignoring this for reading a valid entry after timeout or flush.
				// This can occur if the producer submitted to the ring buffer
				// with BPF_RB_NO_WAKEUP.
				r.pendingErr = err
			} else if err != nil {
				return err
			}
			r.haveData = true
		}

		for {
			err := r.ring.readRecord(rec)
			// Not using errors.Is which is quite a bit slower
			// For a tight loop it might make a difference
			if err == errBusy {
				continue
			}
			if err == errEOR {
				r.haveData = false
				break
			}
			return err
		}
	}
}

// BufferSize returns the size in bytes of the ring buffer
func (r *Reader) BufferSize() int {
	return r.bufferSize
}

// Flush unblocks Read/ReadInto and successive Read/ReadInto calls will return pending samples at this point,
// until you receive a ErrFlushed error.
func (r *Reader) Flush() error {
	return r.poller.Flush()
}

// AvailableBytes returns the amount of data available to read in the ring buffer in bytes.
func (r *Reader) AvailableBytes() int {
	// Don't need to acquire the lock here since the implementation of AvailableBytes
	// performs atomic loads on the producer and consumer positions.
	return int(r.ring.AvailableBytes())
}
