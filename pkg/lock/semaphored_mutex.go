// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Authors of Cilium

package lock

import (
	"context"

	"golang.org/x/sync/semaphore"
)

// SemaphoredMutex is a semaphored mutex that provides a RWLocker interface.
type SemaphoredMutex struct {
	semaphore *semaphore.Weighted
}

// using the same value set in `go/src/rwmutex.go#rwmutexMaxReaders
const maxReaders = 1 << 30

// NewSemaphoredMutex returns a new SemaphoredMutex.
func NewSemaphoredMutex() SemaphoredMutex {
	return SemaphoredMutex{
		semaphore: semaphore.NewWeighted(maxReaders),
	}
}

func (i *SemaphoredMutex) Lock() {
	// It's fine ignoring error since the error is only caused by passing a
	// context with a deadline.
	i.semaphore.Acquire(context.Background(), maxReaders)
}

// UnlockToRLock releases the current lock for writing but it still keeps it
// for reading purposes.
func (i *SemaphoredMutex) UnlockToRLock() {
	i.semaphore.Release(maxReaders - 1)
}

func (i *SemaphoredMutex) Unlock() {
	i.semaphore.Release(maxReaders)
}

func (i *SemaphoredMutex) RLock() {
	// It's fine ignoring error since the error is only caused by passing a
	// context with a deadline.
	i.semaphore.Acquire(context.Background(), 1)
}

func (i *SemaphoredMutex) RUnlock() {
	i.semaphore.Release(1)
}
