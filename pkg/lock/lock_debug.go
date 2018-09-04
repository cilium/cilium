// +build lockdebug

// Copyright 2017-2018 Authors of Cilium
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
	"time"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/stackdump"

	"github.com/sasha-s/go-deadlock"
)

const (
	// selfishThresholdSec is the number of seconds that should be used when
	// detecting if a lock was held for more than the specified time.
	selfishThresholdSec = 0.1

	// Waiting for a lock for longer than DeadlockTimeout is considered a deadlock.
	// Ignored is DeadlockTimeout <= 0.
	deadLockTimeout = 310 * time.Second
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "lock-lib")
)

func init() {
	deadlock.Opts.DeadlockTimeout = deadLockTimeout
}

type internalRWMutex struct {
	deadlock.RWMutex
	time.Time
}

func (i *internalRWMutex) Lock() {
	i.RWMutex.Lock()
	i.Time = time.Now()
}

func (i *internalRWMutex) Unlock() {
	if sec := time.Since(i.Time).Seconds(); sec >= selfishThresholdSec {
		lockDurationWarning(sec)
	}
	i.RWMutex.Unlock()
}

func (i *internalRWMutex) UnlockIgnoreTime() {
	i.RWMutex.Unlock()
}

func (i *internalRWMutex) RLock() {
	i.RWMutex.Lock()
	i.Time = time.Now()
}

func (i *internalRWMutex) RUnlock() {
	if sec := time.Since(i.Time).Seconds(); sec >= selfishThresholdSec {
		lockDurationWarning(sec)
	}
	i.RWMutex.Unlock()
}

func (i *internalRWMutex) RUnlockIgnoreTime() {
	i.RWMutex.Unlock()
}

type internalMutex struct {
	deadlock.Mutex
	time.Time
}

func (i *internalMutex) Lock() {
	i.Mutex.Lock()
	i.Time = time.Now()
}

func (i *internalMutex) Unlock() {
	if sec := time.Since(i.Time).Seconds(); sec >= selfishThresholdSec {
		lockDurationWarning(sec)
	}
	i.Mutex.Unlock()
}

func (i *internalMutex) UnlockIgnoreTime() {
	i.Mutex.Unlock()
}

func lockDurationWarning(sec float64) {
	stackdump.Errorf("Goroutine took lock for more than %.2f, lock was held for %f seconds", selfishThresholdSec, sec)
}
