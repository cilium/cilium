// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lock

import (
	"testing"
)

func TestLock(t *testing.T) {
	var lock1 RWMutex
	lock1.Lock()
	lock1.Unlock()

	lock1.RLock()
	lock1.RUnlock()

	var lock2 Mutex
	lock2.Lock()
	lock2.Unlock()
}

func TestDebugLock(t *testing.T) {
	var lock1 RWMutexDebug
	lock1.Lock()
	lock1.Unlock()

	lock1.RLock()
	lock1.RUnlock()

	var lock2 MutexDebug
	lock2.Lock()
	lock2.Unlock()
}
