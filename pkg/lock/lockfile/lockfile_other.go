// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package lockfile

import (
	"context"
	"fmt"
)

// Lockfile is a simple wrapper around POSIX file locking
// but it uses Linux's per-fd locks, which makes it safe to
// use within the same process
type Lockfile struct {
}

// NewLockfile creates and opens a lockfile, but does not acquire
// a lock.
func NewLockfile(path string) (*Lockfile, error) {
	return nil, fmt.Errorf("not implemented")
}

func (l *Lockfile) Close() error {
	return fmt.Errorf("not implemented")
}

func (l *Lockfile) TryLock(exclusive bool) error {
	return fmt.Errorf("not implemented")
}

func (l *Lockfile) Lock(ctx context.Context, exclusive bool) error {
	return fmt.Errorf("not implemented")
}

func (l *Lockfile) Unlock() error {
	return fmt.Errorf("not implemented")
}
