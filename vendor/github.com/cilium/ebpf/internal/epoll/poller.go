//go:build linux

package epoll

import (
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
)

var (
	ErrFlushed                   = errors.New("data was flushed")
	errEpollWaitDeadlineExceeded = fmt.Errorf("epoll wait: %w", os.ErrDeadlineExceeded)
	errEpollWaitClosed           = fmt.Errorf("epoll wait: %w", os.ErrClosed)
)

// Poller waits for readiness notifications from multiple file descriptors.
//
// The wait can be interrupted by calling Close.
type Poller struct {
	// mutexes protect the fields declared below them. If you need to
	// acquire both at once you must lock epollMu before eventMu.
	epollMu sync.Mutex
	epollFd int

	eventMu    sync.Mutex
	closeEvent *eventFd
	flushEvent *eventFd
}

func New() (_ *Poller, err error) {
	closeFDOnError := func(fd int) {
		if err != nil {
			unix.Close(fd)
		}
	}
	closeEventFDOnError := func(e *eventFd) {
		if err != nil {
			e.close()
		}
	}

	epollFd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("create epoll fd: %w", err)
	}
	defer closeFDOnError(epollFd)

	p := &Poller{epollFd: epollFd}
	p.closeEvent, err = newEventFd()
	if err != nil {
		return nil, err
	}
	defer closeEventFDOnError(p.closeEvent)

	p.flushEvent, err = newEventFd()
	if err != nil {
		return nil, err
	}
	defer closeEventFDOnError(p.flushEvent)

	if err := p.Add(p.closeEvent.raw, 0); err != nil {
		return nil, fmt.Errorf("add close eventfd: %w", err)
	}

	if err := p.Add(p.flushEvent.raw, 0); err != nil {
		return nil, fmt.Errorf("add flush eventfd: %w", err)
	}

	runtime.SetFinalizer(p, (*Poller).Close)
	return p, nil
}

// Close the poller.
//
// Interrupts any calls to Wait. Multiple calls to Close are valid, but subsequent
// calls will return os.ErrClosed.
func (p *Poller) Close() error {
	runtime.SetFinalizer(p, nil)

	// Interrupt Wait() via the closeEvent fd if it's currently blocked.
	if err := p.wakeWaitForClose(); err != nil {
		return err
	}

	// Acquire the lock. This ensures that Wait isn't running.
	p.epollMu.Lock()
	defer p.epollMu.Unlock()

	// Prevent other calls to Close().
	p.eventMu.Lock()
	defer p.eventMu.Unlock()

	if p.epollFd != -1 {
		unix.Close(p.epollFd)
		p.epollFd = -1
	}

	if p.closeEvent != nil {
		p.closeEvent.close()
		p.closeEvent = nil
	}

	if p.flushEvent != nil {
		p.flushEvent.close()
		p.flushEvent = nil
	}

	return nil
}

// Add an fd to the poller.
//
// id is returned by Wait in the unix.EpollEvent.Pad field any may be zero. It
// must not exceed math.MaxInt32.
//
// Add is blocked by Wait.
func (p *Poller) Add(fd int, id int) error {
	if int64(id) > math.MaxInt32 {
		return fmt.Errorf("unsupported id: %d", id)
	}

	p.epollMu.Lock()
	defer p.epollMu.Unlock()

	if p.epollFd == -1 {
		return fmt.Errorf("epoll add: %w", os.ErrClosed)
	}

	// The representation of EpollEvent isn't entirely accurate.
	// Pad is fully usable, not just padding. Hence we stuff the
	// id in there, which allows us to identify the event later (e.g.,
	// in case of perf events, which CPU sent it).
	event := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(fd),
		Pad:    int32(id),
	}

	if err := unix.EpollCtl(p.epollFd, unix.EPOLL_CTL_ADD, fd, &event); err != nil {
		return fmt.Errorf("add fd to epoll: %v", err)
	}

	return nil
}

// Wait for events.
//
// Returns the number of pending events and any errors.
//
//   - [os.ErrClosed] if interrupted by [Close].
//   - [ErrFlushed] if interrupted by [Flush].
//   - [os.ErrDeadlineExceeded] if deadline is reached.
func (p *Poller) Wait(events []unix.EpollEvent, deadline time.Time) (int, error) {
	p.epollMu.Lock()
	defer p.epollMu.Unlock()

	if p.epollFd == -1 {
		return 0, errEpollWaitClosed
	}

	for {
		timeout := int(-1)
		if !deadline.IsZero() {
			// Ensure deadline is not in the past and not too far into the future.
			timeout = int(internal.Between(time.Until(deadline).Milliseconds(), 0, math.MaxInt))
		}

		n, err := unix.EpollWait(p.epollFd, events, timeout)
		if temp, ok := err.(temporaryError); ok && temp.Temporary() {
			// Retry the syscall if we were interrupted, see https://github.com/golang/go/issues/20400
			continue
		}

		if err != nil {
			return 0, err
		}

		if n == 0 {
			return 0, errEpollWaitDeadlineExceeded
		}

		for i := 0; i < n; {
			event := events[i]
			if int(event.Fd) == p.closeEvent.raw {
				// Since we don't read p.closeEvent the event is never cleared and
				// we'll keep getting this wakeup until Close() acquires the
				// lock and sets p.epollFd = -1.
				return 0, errEpollWaitClosed
			}
			if int(event.Fd) == p.flushEvent.raw {
				// read event to prevent it from continuing to wake
				p.flushEvent.read()
				err = ErrFlushed
				events = slices.Delete(events, i, i+1)
				n -= 1
				continue
			}
			i++
		}

		return n, err
	}
}

type temporaryError interface {
	Temporary() bool
}

// wakeWaitForClose unblocks Wait if it's epoll_wait.
func (p *Poller) wakeWaitForClose() error {
	p.eventMu.Lock()
	defer p.eventMu.Unlock()

	if p.closeEvent == nil {
		return fmt.Errorf("epoll wake: %w", os.ErrClosed)
	}

	return p.closeEvent.add(1)
}

// Flush unblocks Wait if it's epoll_wait, for purposes of reading pending samples
func (p *Poller) Flush() error {
	p.eventMu.Lock()
	defer p.eventMu.Unlock()

	if p.flushEvent == nil {
		return fmt.Errorf("epoll wake: %w", os.ErrClosed)
	}

	return p.flushEvent.add(1)
}

// eventFd wraps a Linux eventfd.
//
// An eventfd acts like a counter: writes add to the counter, reads retrieve
// the counter and reset it to zero. Reads also block if the counter is zero.
//
// See man 2 eventfd.
type eventFd struct {
	file *os.File
	// prefer raw over file.Fd(), since the latter puts the file into blocking
	// mode.
	raw int
}

func newEventFd() (*eventFd, error) {
	fd, err := unix.Eventfd(0, unix.O_CLOEXEC|unix.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "event")
	return &eventFd{file, fd}, nil
}

func (efd *eventFd) close() error {
	return efd.file.Close()
}

func (efd *eventFd) add(n uint64) error {
	var buf [8]byte
	internal.NativeEndian.PutUint64(buf[:], n)
	_, err := efd.file.Write(buf[:])
	return err
}

func (efd *eventFd) read() (uint64, error) {
	var buf [8]byte
	_, err := efd.file.Read(buf[:])
	return internal.NativeEndian.Uint64(buf[:]), err
}
