package perf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/epoll"
	"github.com/cilium/ebpf/internal/unix"
)

var (
	ErrClosed = os.ErrClosed
	errEOR    = errors.New("end of ring")
)

// perfEventHeader must match 'struct perf_event_header` in <linux/perf_event.h>.
type perfEventHeader struct {
	Type uint32
	Misc uint16
	Size uint16
}

func cpuForEvent(event *unix.EpollEvent) int {
	return int(event.Pad)
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
}

// NB: Has to be preceded by a call to ring.loadHead.
func readRecordFromRing(ring *perfEventRing) (Record, error) {
	defer ring.writeTail()
	return readRecord(ring, ring.cpu)
}

func readRecord(rd io.Reader, cpu int) (Record, error) {
	var header perfEventHeader
	err := binary.Read(rd, internal.NativeEndian, &header)
	if err == io.EOF {
		return Record{}, errEOR
	}

	if err != nil {
		return Record{}, fmt.Errorf("can't read event header: %v", err)
	}

	switch header.Type {
	case unix.PERF_RECORD_LOST:
		lost, err := readLostRecords(rd)
		return Record{CPU: cpu, LostSamples: lost}, err

	case unix.PERF_RECORD_SAMPLE:
		sample, err := readRawSample(rd)
		return Record{CPU: cpu, RawSample: sample}, err

	default:
		return Record{}, &unknownEventError{header.Type}
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

func readRawSample(rd io.Reader) ([]byte, error) {
	// This must match 'struct perf_event_sample in kernel sources.
	var size uint32
	if err := binary.Read(rd, internal.NativeEndian, &size); err != nil {
		return nil, fmt.Errorf("can't read sample size: %v", err)
	}

	data := make([]byte, int(size))
	if _, err := io.ReadFull(rd, data); err != nil {
		return nil, fmt.Errorf("can't read sample: %v", err)
	}
	return data, nil
}

// Reader allows reading bpf_perf_event_output
// from user space.
type Reader struct {
	poller *epoll.Poller

	// mu protects read/write access to the Reader structure with the
	// exception of 'pauseFds', which is protected by 'pauseMu'.
	// If locking both 'mu' and 'pauseMu', 'mu' must be locked first.
	mu sync.Mutex

	// Closing a PERF_EVENT_ARRAY removes all event fds
	// stored in it, so we keep a reference alive.
	array       *ebpf.Map
	rings       []*perfEventRing
	epollEvents []unix.EpollEvent
	epollRings  []*perfEventRing

	// pauseFds are a copy of the fds in 'rings', protected by 'pauseMu'.
	// These allow Pause/Resume to be executed independently of any ongoing
	// Read calls, which would otherwise need to be interrupted.
	pauseMu  sync.Mutex
	pauseFds []int
}

// ReaderOptions control the behaviour of the user
// space reader.
type ReaderOptions struct {
	// The number of written bytes required in any per CPU buffer before
	// Read will process data. Must be smaller than PerCPUBuffer.
	// The default is to start processing as soon as data is available.
	Watermark int
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
	if perCPUBuffer < 1 {
		return nil, errors.New("perCPUBuffer must be larger than 0")
	}

	var (
		fds      []int
		nCPU     = int(array.MaxEntries())
		rings    = make([]*perfEventRing, 0, nCPU)
		pauseFds = make([]int, 0, nCPU)
	)

	poller, err := epoll.New()
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			poller.Close()
			for _, fd := range fds {
				unix.Close(fd)
			}
			for _, ring := range rings {
				if ring != nil {
					ring.Close()
				}
			}
		}
	}()

	// bpf_perf_event_output checks which CPU an event is enabled on,
	// but doesn't allow using a wildcard like -1 to specify "all CPUs".
	// Hence we have to create a ring for each CPU.
	for i := 0; i < nCPU; i++ {
		ring, err := newPerfEventRing(i, perCPUBuffer, opts.Watermark)
		if errors.Is(err, unix.ENODEV) {
			// The requested CPU is currently offline, skip it.
			rings = append(rings, nil)
			pauseFds = append(pauseFds, -1)
			continue
		}

		if err != nil {
			return nil, fmt.Errorf("failed to create perf ring for CPU %d: %v", i, err)
		}
		rings = append(rings, ring)
		pauseFds = append(pauseFds, ring.fd)

		if err := poller.Add(ring.fd, i); err != nil {
			return nil, err
		}
	}

	array, err = array.Clone()
	if err != nil {
		return nil, err
	}

	pr = &Reader{
		array:       array,
		rings:       rings,
		poller:      poller,
		epollEvents: make([]unix.EpollEvent, len(rings)),
		epollRings:  make([]*perfEventRing, 0, len(rings)),
		pauseFds:    pauseFds,
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
	// lock so that we can clean up.
	pr.mu.Lock()
	defer pr.mu.Unlock()

	for _, ring := range pr.rings {
		if ring != nil {
			ring.Close()
		}
	}
	pr.rings = nil
	pr.pauseFds = nil
	pr.array.Close()

	return nil
}

// Read the next record from the perf ring buffer.
//
// The function blocks until there are at least Watermark bytes in one
// of the per CPU buffers. Records from buffers below the Watermark
// are not returned.
//
// Records can contain between 0 and 7 bytes of trailing garbage from the ring
// depending on the input sample's length.
//
// Calling Close interrupts the function.
func (pr *Reader) Read() (Record, error) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if pr.rings == nil {
		return Record{}, fmt.Errorf("perf ringbuffer: %w", ErrClosed)
	}

	for {
		if len(pr.epollRings) == 0 {
			nEvents, err := pr.poller.Wait(pr.epollEvents)
			if err != nil {
				return Record{}, err
			}

			for _, event := range pr.epollEvents[:nEvents] {
				ring := pr.rings[cpuForEvent(&event)]
				pr.epollRings = append(pr.epollRings, ring)

				// Read the current head pointer now, not every time
				// we read a record. This prevents a single fast producer
				// from keeping the reader busy.
				ring.loadHead()
			}
		}

		// Start at the last available event. The order in which we
		// process them doesn't matter, and starting at the back allows
		// resizing epollRings to keep track of processed rings.
		record, err := readRecordFromRing(pr.epollRings[len(pr.epollRings)-1])
		if err == errEOR {
			// We've emptied the current ring buffer, process
			// the next one.
			pr.epollRings = pr.epollRings[:len(pr.epollRings)-1]
			continue
		}

		return record, err
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

	if pr.pauseFds == nil {
		return fmt.Errorf("%w", ErrClosed)
	}

	for i := range pr.pauseFds {
		if err := pr.array.Delete(uint32(i)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("could't delete event fd for CPU %d: %w", i, err)
		}
	}

	return nil
}

// Resume allows this perf reader to emit notifications.
//
// Subsequent calls to Read will block until the next event notification.
func (pr *Reader) Resume() error {
	pr.pauseMu.Lock()
	defer pr.pauseMu.Unlock()

	if pr.pauseFds == nil {
		return fmt.Errorf("%w", ErrClosed)
	}

	for i, fd := range pr.pauseFds {
		if fd == -1 {
			continue
		}

		if err := pr.array.Put(uint32(i), uint32(fd)); err != nil {
			return fmt.Errorf("couldn't put event fd %d for CPU %d: %w", fd, i, err)
		}
	}

	return nil
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
