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

// SemaphoredMutex is a semaphored mutex that provodes a RWLocker interface.
type SemaphoredMutex struct {
	*semaphore.Weighted
}

// using the same value set in `go/src/rwmutex.go#rwmutexMaxReaders
const maxReaders = 1 << 30

// NewSemaphoredMutex returns a new SemaphoredMutex.
func NewSemaphoredMutex() *SemaphoredMutex {
	return &SemaphoredMutex{
		Weighted: semaphore.NewWeighted(maxReaders),
	}
}

func (i *SemaphoredMutex) Lock() {
	i.Acquire(context.Background(), maxReaders)
}

func (i *SemaphoredMutex) UnlockToRLock() {
	i.Release(maxReaders - 1)
}

func (i *SemaphoredMutex) Unlock() {
	i.Release(maxReaders)
}

func (i *SemaphoredMutex) RLock() {
	i.Acquire(context.Background(), 1)
}

func (i *SemaphoredMutex) RUnlock() {
	i.Release(1)
}
