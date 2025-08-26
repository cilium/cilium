// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package lockfile

import (
	"context"
	"fmt"
	"os"
	"syscall"
)

// Lockfile is a simple wrapper around POSIX file locking
// but it uses Linux's per-fd locks, which makes it safe to
// use within the same process
type Lockfile struct {
	fp *os.File
}

// Linux supports per-file-descriptor locks, which are safer
// and, more importantly, testable

const (
	SETLK  = 37 // F_OFD_SETLK
	SETLKW = 38 // F_OFD_SETLKW
)

// NewLockfile creates and opens a lockfile, but does not acquire
// a lock.
func NewLockfile(path string) (*Lockfile, error) {
	fp, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to create lockfile %s: %w", path, err)
	}

	return &Lockfile{
		fp: fp,
	}, nil
}

// Close will close the file, which implicitly removes all locks held.
// It is an error to re-use a closed Lockfile.
func (l *Lockfile) Close() error {
	fp := l.fp
	l.fp = nil
	return fp.Close()
}

// TryLock will attempt to take a lock, returining error if it is not
// possible to acquire the lock.
// If exclusive is true, then it will attempt to obtain a write, or exclusive, lock
func (l *Lockfile) TryLock(exclusive bool) error {
	return l.flock(context.Background(), false, exclusive, false)
}

// Lock will attempt to take a lock, blocking until it is able to do so.
// If exclusive is true, then it will obtain a write, or exclusive, lock
func (l *Lockfile) Lock(ctx context.Context, exclusive bool) error {
	return l.flock(ctx, false, exclusive, true)
}

// Unlock removes the lock, but keeps the file open.
func (l *Lockfile) Unlock() error {
	return l.flock(context.Background(), true, false, false)
}

// flock will perform the lock operation
// - unlock: if true, remove the lock
// - exclusive: if true, then obtain a write lock, else a read lock
// - wait: if true, then block until the lock is obtained. Ignored when unlocking
func (l *Lockfile) flock(ctx context.Context, unlock, exclusive, wait bool) error {
	var lockType int16 = syscall.F_RDLCK
	if unlock {
		lockType = syscall.F_UNLCK // unlock is a lockType!? What an API.
	} else if exclusive {
		lockType = syscall.F_WRLCK
	}

	command := SETLK
	if !unlock && wait {
		command = SETLKW
	}

	flockT := syscall.Flock_t{
		Type:   lockType,
		Whence: 0,
		Start:  0,
		Len:    0,
	}

	// if no context is supplied, or the context is non-cancellable,
	// then don't do the goroutine dance
	if ctx.Done() == nil {
		return syscall.FcntlFlock(l.fp.Fd(), command, &flockT)
	}

	// syscalls can't be cancelled, so just wrap in a goroutine so we can
	// return early if the context closes
	lockCh := make(chan error, 1)
	go func() {
		lockCh <- syscall.FcntlFlock(l.fp.Fd(), command, &flockT)
	}()
	select {
	case err := <-lockCh:
		return err
	case <-ctx.Done():
		// oops, we cancelled
		// spin up a goroutine to drop the lock when we get it,
		// since syscalls can't actually be cancelled
		go func() {
			err := <-lockCh
			if err == nil {
				l.flock(context.Background(), true, false, false)
			}
		}()
		return ctx.Err()
	}
}
