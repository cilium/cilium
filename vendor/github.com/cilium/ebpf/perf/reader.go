//go:build linux

package perf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/epoll"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

var (
	ErrClosed  = os.ErrClosed
	ErrFlushed = epoll.ErrFlushed
	errEOR     = errors.New("end of ring")
)

var perfEventHeaderSize = binary.Size(perfEventHeader{})

// perfEventHeader must match 'struct perf_event_header` in <linux/perf_event.h>.
type perfEventHeader struct {
	Type uint32
	Misc uint16
	Size uint16
}

// Record contains either a sample or a counter of the
// number of lost samples.
type Record struct {
	// The CPU this record was generated on.
	CPU int

	// The data submitted via bpf_perf_event_output.
	// Due to a kernel bug, this can contain between 0 and 7 bytes of trailing
	// garbage from the ring depending on the input sample's length.
	RawSample []byte

	// The number of samples which could not be output, since
	// the ring buffer was full.
	LostSamples uint64

	// The minimum number of bytes remaining in the per-CPU buffer after this Record has been read.
	// Negative for overwritable buffers.
	Remaining int
}

// Read a record from a reader and tag it as being from the given CPU.
//
// buf must be at least perfEventHeaderSize bytes long.
func readRecord(rd io.Reader, rec *Record, buf []byte, overwritable bool) error {
	// Assert that the buffer is large enough.
	buf = buf[:perfEventHeaderSize]
	_, err := io.ReadFull(rd, buf)
	if errors.Is(err, io.EOF) {
		return errEOR
	} else if err != nil {
		return fmt.Errorf("read perf event header: %v", err)
	}

	header := perfEventHeader{
		internal.NativeEndian.Uint32(buf[0:4]),
		internal.NativeEndian.Uint16(buf[4:6]),
		internal.NativeEndian.Uint16(buf[6:8]),
	}

	switch header.Type {
	case unix.PERF_RECORD_LOST:
		rec.RawSample = rec.RawSample[:0]
		rec.LostSamples, err = readLostRecords(rd)
		return err

	case unix.PERF_RECORD_SAMPLE:
		rec.LostSamples = 0
		// We can reuse buf here because perfEventHeaderSize > perfEventSampleSize.
		rec.RawSample, err = readRawSample(rd, buf, rec.RawSample)
		return err

	default:
		return &unknownEventError{header.Type}
	}
}

func readLostRecords(rd io.Reader) (uint64, error) {
	// lostHeader must match 'struct perf_event_lost in kernel sources.
	var lostHeader struct {
		ID   uint64
		Lost uint64
	}

	err := binary.Read(rd, internal.NativeEndian, &lostHeader)
	if err != nil {
		return 0, fmt.Errorf("can't read lost records header: %v", err)
	}

	return lostHeader.Lost, nil
}

var perfEventSampleSize = binary.Size(uint32(0))

// This must match 'struct perf_event_sample in kernel sources.
type perfEventSample struct {
	Size uint32
}

func readRawSample(rd io.Reader, buf, sampleBuf []byte) ([]byte, error) {
	buf = buf[:perfEventSampleSize]
	if _, err := io.ReadFull(rd, buf); err != nil {
		return nil, fmt.Errorf("read sample size: %w", err)
	}

	sample := perfEventSample{
		internal.NativeEndian.Uint32(buf),
	}

	var data []byte
	if size := int(sample.Size); cap(sampleBuf) < size {
		data = make([]byte, size)
	} else {
		data = sampleBuf[:size]
	}

	if _, err := io.ReadFull(rd, data); err != nil {
		return nil, fmt.Errorf("read sample: %w", err)
	}
	return data, nil
}

// Reader allows reading bpf_perf_event_output
// from user space.
type Reader struct {
	poller *epoll.Poller

	// mu protects read/write access to the Reader structure with the
	// exception fields protected by 'pauseMu'.
	// If locking both 'mu' and 'pauseMu', 'mu' must be locked first.
	mu           sync.Mutex
	array        *ebpf.Map
	rings        []*perfEventRing
	epollEvents  []unix.EpollEvent
	epollRings   []*perfEventRing
	eventHeader  []byte
	deadline     time.Time
	overwritable bool
	bufferSize   int
	pendingErr   error

	// pauseMu protects eventFds so that Pause / Resume can be invoked while
	// Read is blocked.
	pauseMu  sync.Mutex
	eventFds []*sys.FD
	paused   bool
}

// ReaderOptions control the behaviour of the user
// space reader.
type ReaderOptions struct {
	// The number of events required in any per CPU buffer before
	// Read will process data. This is mutually exclusive with Watermark.
	// The default is zero, which means Watermark will take precedence.
	WakeupEvents int
	// The number of written bytes required in any per CPU buffer before
	// Read will process data. Must be smaller than PerCPUBuffer.
	// The default is to start processing as soon as data is available.
	Watermark int
	// This perf ring buffer is overwritable, once full the oldest event will be
	// overwritten by newest.
	Overwritable bool
}

// NewReader creates a new reader with default options.
//
// array must be a PerfEventArray. perCPUBuffer gives the size of the
// per CPU buffer in bytes. It is rounded up to the nearest multiple
// of the current page size.
func NewReader(array *ebpf.Map, perCPUBuffer int) (*Reader, error) {
	return NewReaderWithOptions(array, perCPUBuffer, ReaderOptions{})
}

// NewReaderWithOptions creates a new reader with the given options.
func NewReaderWithOptions(array *ebpf.Map, perCPUBuffer int, opts ReaderOptions) (pr *Reader, err error) {
	closeOnError := func(c io.Closer) {
		if err != nil {
			c.Close()
		}
	}

	if perCPUBuffer < 1 {
		return nil, errors.New("perCPUBuffer must be larger than 0")
	}
	if opts.WakeupEvents > 0 && opts.Watermark > 0 {
		return nil, errors.New("WakeupEvents and Watermark cannot both be non-zero")
	}

	var (
		nCPU     = int(array.MaxEntries())
		rings    = make([]*perfEventRing, 0, nCPU)
		eventFds = make([]*sys.FD, 0, nCPU)
	)

	poller, err := epoll.New()
	if err != nil {
		return nil, err
	}
	defer closeOnError(poller)

	// bpf_perf_event_output checks which CPU an event is enabled on,
	// but doesn't allow using a wildcard like -1 to specify "all CPUs".
	// Hence we have to create a ring for each CPU.
	bufferSize := 0
	for i := 0; i < nCPU; i++ {
		event, ring, err := newPerfEventRing(i, perCPUBuffer, opts)
		if errors.Is(err, unix.ENODEV) {
			// The requested CPU is currently offline, skip it.
			continue
		}

		if err != nil {
			return nil, fmt.Errorf("failed to create perf ring for CPU %d: %v", i, err)
		}
		defer closeOnError(event)
		defer closeOnError(ring)

		bufferSize = ring.size()
		rings = append(rings, ring)
		eventFds = append(eventFds, event)

		if err := poller.Add(event.Int(), 0); err != nil {
			return nil, err
		}
	}

	// Closing a PERF_EVENT_ARRAY removes all event fds
	// stored in it, so we keep a reference alive.
	array, err = array.Clone()
	if err != nil {
		return nil, err
	}

	pr = &Reader{
		array:        array,
		rings:        rings,
		poller:       poller,
		deadline:     time.Time{},
		epollEvents:  make([]unix.EpollEvent, len(rings)),
		epollRings:   make([]*perfEventRing, 0, len(rings)),
		eventHeader:  make([]byte, perfEventHeaderSize),
		eventFds:     eventFds,
		overwritable: opts.Overwritable,
		bufferSize:   bufferSize,
	}
	if err = pr.Resume(); err != nil {
		return nil, err
	}
	runtime.SetFinalizer(pr, (*Reader).Close)
	return pr, nil
}

// Close frees resources used by the reader.
//
// It interrupts calls to Read.
//
// Calls to perf_event_output from eBPF programs will return
// ENOENT after calling this method.
func (pr *Reader) Close() error {
	if err := pr.poller.Close(); err != nil {
		if errors.Is(err, os.ErrClosed) {
			return nil
		}
		return fmt.Errorf("close poller: %w", err)
	}

	// Trying to poll will now fail, so Read() can't block anymore. Acquire the
	// locks so that we can clean up.
	pr.mu.Lock()
	defer pr.mu.Unlock()

	pr.pauseMu.Lock()
	defer pr.pauseMu.Unlock()

	for _, ring := range pr.rings {
		ring.Close()
	}
	for _, event := range pr.eventFds {
		event.Close()
	}
	pr.rings = nil
	pr.eventFds = nil
	pr.array.Close()

	return nil
}

// SetDeadline controls how long Read and ReadInto will block waiting for samples.
//
// Passing a zero time.Time will remove the deadline. Passing a deadline in the
// past will prevent the reader from blocking if there are no records to be read.
func (pr *Reader) SetDeadline(t time.Time) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	pr.deadline = t
}

// Read the next record from the perf ring buffer.
//
// The method blocks until there are at least Watermark bytes in one
// of the per CPU buffers. Records from buffers below the Watermark
// are not returned.
//
// Records can contain between 0 and 7 bytes of trailing garbage from the ring
// depending on the input sample's length.
//
// Calling [Close] interrupts the method with [os.ErrClosed]. Calling [Flush]
// makes it return all records currently in the ring buffer, followed by [ErrFlushed].
//
// Returns [os.ErrDeadlineExceeded] if a deadline was set and after all records
// have been read from the ring.
//
// See [Reader.ReadInto] for a more efficient version of this method.
func (pr *Reader) Read() (Record, error) {
	var r Record

	return r, pr.ReadInto(&r)
}

var errMustBePaused = fmt.Errorf("perf ringbuffer: must have been paused before reading overwritable buffer")

// ReadInto is like [Reader.Read] except that it allows reusing Record and associated buffers.
func (pr *Reader) ReadInto(rec *Record) error {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	pr.pauseMu.Lock()
	defer pr.pauseMu.Unlock()

	if pr.overwritable && !pr.paused {
		return errMustBePaused
	}

	if pr.rings == nil {
		return fmt.Errorf("perf ringbuffer: %w", ErrClosed)
	}

	for {
		if len(pr.epollRings) == 0 {
			if pe := pr.pendingErr; pe != nil {
				// All rings have been emptied since the error occurred, return
				// appropriate error.
				pr.pendingErr = nil
				return pe
			}

			// NB: The deferred pauseMu.Unlock will panic if Wait panics, which
			// might obscure the original panic.
			pr.pauseMu.Unlock()
			_, err := pr.poller.Wait(pr.epollEvents, pr.deadline)
			pr.pauseMu.Lock()

			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ErrFlushed) {
				// We've hit the deadline, check whether there is any data in
				// the rings that we've not been woken up for.
				pr.pendingErr = err
			} else if err != nil {
				return err
			}

			// Re-validate pr.paused since we dropped pauseMu.
			if pr.overwritable && !pr.paused {
				return errMustBePaused
			}

			// Waking up userspace is expensive, make the most of it by checking
			// all rings.
			for _, ring := range pr.rings {
				ring.loadHead()
				pr.epollRings = append(pr.epollRings, ring)
			}
		}

		// Start at the last available event. The order in which we
		// process them doesn't matter, and starting at the back allows
		// resizing epollRings to keep track of processed rings.
		err := pr.readRecordFromRing(rec, pr.epollRings[len(pr.epollRings)-1])
		if err == errEOR {
			// We've emptied the current ring buffer, process
			// the next one.
			pr.epollRings = pr.epollRings[:len(pr.epollRings)-1]
			continue
		}

		return err
	}
}

// Pause stops all notifications from this Reader.
//
// While the Reader is paused, any attempts to write to the event buffer from
// BPF programs will return -ENOENT.
//
// Subsequent calls to Read will block until a call to Resume.
func (pr *Reader) Pause() error {
	pr.pauseMu.Lock()
	defer pr.pauseMu.Unlock()

	if pr.eventFds == nil {
		return fmt.Errorf("%w", ErrClosed)
	}

	for i := range pr.eventFds {
		if err := pr.array.Delete(uint32(i)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("could't delete event fd for CPU %d: %w", i, err)
		}
	}

	pr.paused = true

	return nil
}

// Resume allows this perf reader to emit notifications.
//
// Subsequent calls to Read will block until the next event notification.
func (pr *Reader) Resume() error {
	pr.pauseMu.Lock()
	defer pr.pauseMu.Unlock()

	if pr.eventFds == nil {
		return fmt.Errorf("%w", ErrClosed)
	}

	for i, fd := range pr.eventFds {
		if fd == nil {
			continue
		}

		if err := pr.array.Put(uint32(i), fd.Uint()); err != nil {
			return fmt.Errorf("couldn't put event fd %d for CPU %d: %w", fd, i, err)
		}
	}

	pr.paused = false

	return nil
}

// BufferSize is the size in bytes of each per-CPU buffer
func (pr *Reader) BufferSize() int {
	return pr.bufferSize
}

// Flush unblocks Read/ReadInto and successive Read/ReadInto calls will return pending samples at this point,
// until you receive a [ErrFlushed] error.
func (pr *Reader) Flush() error {
	return pr.poller.Flush()
}

// NB: Has to be preceded by a call to ring.loadHead.
func (pr *Reader) readRecordFromRing(rec *Record, ring *perfEventRing) error {
	defer ring.writeTail()

	rec.CPU = ring.cpu
	err := readRecord(ring, rec, pr.eventHeader, pr.overwritable)
	if pr.overwritable && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
		return errEOR
	}
	rec.Remaining = ring.remaining()
	return err
}

type unknownEventError struct {
	eventType uint32
}

func (uev *unknownEventError) Error() string {
	return fmt.Sprintf("unknown event type: %d", uev.eventType)
}

// IsUnknownEvent returns true if the error occurred
// because an unknown event was submitted to the perf event ring.
func IsUnknownEvent(err error) bool {
	var uee *unknownEventError
	return errors.As(err, &uee)
}
