// Copyright 2017 Authors of Cilium
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
