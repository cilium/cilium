// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
