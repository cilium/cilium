// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lock

import (
	"github.com/sasha-s/go-deadlock"
)

// RWMutex is equivalent to sync.RWMutex but applies deadlock detection if the
// built tag "lockdebug" is set
type RWMutex struct {
	internalRWMutex
}

// Mutex is equivalent to sync.Mutex but applies deadlock detection if the
// built tag "lockdebug" is set
type Mutex struct {
	internalMutex
}

// RWMutexDebug is a RWMutexDebug with deadlock detection regardless of use of the build tag
type RWMutexDebug struct {
	deadlock.RWMutex
}

// MutexDebug is a MutexDebug with deadlock detection regardless of use of the build tag
type MutexDebug struct {
	deadlock.Mutex
}
