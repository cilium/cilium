// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package netns

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

type NetNS struct {
	f *os.File
}

// newNetNS constructs a new NetNS and supplies it with a finalizer.
func newNetNS(f *os.File) *NetNS {
	ns := &NetNS{f: f}

	// Prevent resource leaks by eventually closing the underlying file descriptor
	// after ns is garbage collected.
	runtime.SetFinalizer(ns, (*NetNS).Close)

	return ns
}

// New creates a network namespace and returns a handle to it.
//
// The namespace created by this call is not pinned and will be closed when the
// last process in the namespace terminates, or when the handle is either
// Close()d explicitly or garbage collected.
//
// Not calling Close() is an error.
func New() (*NetNS, error) {
	var f *os.File

	// Perform network namespace creation in a new goroutine to give us the
	// possibility of terminating the underlying OS thread (by terminating the
	// goroutine) if something goes wrong.
	var g errgroup.Group
	g.Go(func() error {
		restoreUnlock, err := lockOSThread()
		if err != nil {
			return fmt.Errorf("lock OS thread: %w", err)
		}

		// Move the underlying OS thread to a new network namespace. This can be
		// undone by calling restoreUnlock().
		if err := unshare(); err != nil {
			return fmt.Errorf("create new netns: %w", err)
		}

		// Take out a reference to the new netns.
		f, err = getCurrent()
		if err != nil {
			return fmt.Errorf("get current netns: %w (terminating OS thread)", err)
		}

		// Restore the OS thread to its original network namespace or implicitly
		// terminate it if something went wrong.
		if err := restoreUnlock(); err != nil {
			return fmt.Errorf("restore current netns: %w (terminating OS thread)", err)
		}

		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return newNetNS(f), nil
}

// OpenPinned opens a handle to the existing, pinned network namespace at the
// given path. Useful for running code within a netns managed by another process
// that pinned a network namespace to an nsfs.
//
// Not calling Close() is an error.
func OpenPinned(path string) (*NetNS, error) {
	f, err := getFromPath(path)
	if err != nil {
		return nil, err
	}

	return newNetNS(f), nil
}

// Current returns a handle to the network namespace of the calling goroutine's
// underlying OS thread.
func Current() (*NetNS, error) {
	f, err := getCurrent()
	if err != nil {
		return nil, err
	}

	return newNetNS(f), nil
}

// GetNetNSCookie tries to retrieve the cookie of the host netns.
func GetNetNSCookie() (uint64, error) {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(s)

	cookie, err := unix.GetsockoptUint64(s, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err != nil {
		return 0, err
	}

	return cookie, nil
}

// FD returns the underlying file descriptor representing the netns handle.
func (h *NetNS) FD() int {
	if h.f == nil {
		return -1
	}

	return int(h.f.Fd())
}

// Close closes the handle to the network namespace. This does not necessarily
// mean destroying the network namespace itself, which only happens when all
// references to it are gone and all of its processes have been terminated.
func (h *NetNS) Close() error {
	if h.f == nil {
		return nil
	}

	if err := h.f.Close(); err != nil {
		return err
	}
	h.f = nil

	return nil
}

// Do runs the provided func in the netns without changing the calling thread's
// netns.
//
// The code in f and any code called by f must NOT call [runtime.LockOSThread],
// as this could leave the goroutine created by Do permanently pinned to an OS
// thread.
func (h *NetNS) Do(f func() error) error {

	// Start the func in a new goroutine and lock it to an exclusive thread. This
	// ensures that if execution of the goroutine fails unexpectedly before we
	// call UnlockOSThread, the go runtime will ensure the underlying OS thread is
	// disposed of, rather than reused in a potentially undefined state.
	//
	// See also: https://pkg.go.dev/runtime#UnlockOSThread
	var g errgroup.Group
	g.Go(func() error {
		// Lock the newly-created goroutine to the OS thread it's running on so we
		// can safely move it into another network namespace. (per-thread state)
		restoreUnlock, err := lockOSThread()
		if err != nil {
			return err
		}

		if err := set(h.f); err != nil {
			return fmt.Errorf("set netns: %w (terminating OS thread)", err)
		}

		ferr := f()

		// Attempt to restore the underlying OS thread to its original network
		// namespace and unlock the running goroutine from its OS thread. Any
		// failures during this process will leave the goroutine locked, making the
		// underlying OS thread terminate when this function returns.
		if err := restoreUnlock(); err != nil {
			return fmt.Errorf("restore original netns: %w (terminating OS thread)", err)
		}
		return ferr
	})

	return g.Wait()
}

// lockOSThread locks the calling goroutine to its underlying OS thread and
// returns a function that can later be used to unlock and restore the OS thread
// to its network namespace at the time of the initial call.
func lockOSThread() (func() error, error) {
	runtime.LockOSThread()

	orig, err := getCurrent()
	if err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("get current namespace: %w", err)
	}

	return func() error {
		defer orig.Close()

		if err := set(orig); err != nil {
			// We didn't manage to restore the OS thread to its original namespace.
			// Don't unlock the current goroutine from its thread, so the thread will
			// terminate when the current goroutine does.
			return err
		}

		// Original netns was restored, release the OS thread back into the
		// schedulable pool.
		runtime.UnlockOSThread()

		return nil
	}, nil
}

// unshare moves the calling OS thread of the calling goroutine to a new network
// namespace. Must only be called after a prior call to lockOSThread().
func unshare() error {
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return err
	}
	return nil
}

// set sets the underlying OS thread of the calling goroutine to the netns
// pointed at by f.
func set(f *os.File) error {
	return unix.Setns(int(f.Fd()), unix.CLONE_NEWNET)
}

// getCurrent gets a file descriptor to the current thread network namespace.
func getCurrent() (*os.File, error) {
	return getFromThread(os.Getpid(), unix.Gettid())
}

// getFromPath gets a file descriptor to the network namespace pinned at path.
func getFromPath(path string) (*os.File, error) {
	return os.OpenFile(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
}

// getFromThread gets a file descriptor to the network namespace of a given pid
// and tid.
func getFromThread(pid, tid int) (*os.File, error) {
	return getFromPath(fmt.Sprintf("/proc/%d/task/%d/ns/net", pid, tid))
}
