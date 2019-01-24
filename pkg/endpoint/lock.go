// Copyright 2018 Authors of Cilium
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

package endpoint

import "fmt"

// LockAlive returns error if endpoint was removed, locks underlying mutex otherwise
func (e *Endpoint) LockAlive() error {
	e.mutex.Lock()
	if e.IsDisconnecting() {
		e.mutex.Unlock()
		return fmt.Errorf("lock failed: endpoint is in the process of being removed")
	}
	return nil
}

// Unlock unlocks endpoint mutex
func (e *Endpoint) Unlock() {
	e.mutex.Unlock()
}

// RLockAlive returns error if endpoint was removed, read locks underlying mutex otherwise
func (e *Endpoint) RLockAlive() error {
	e.mutex.RLock()
	if e.IsDisconnecting() {
		e.mutex.RUnlock()
		return ErrNotAlive
	}
	return nil
}

// RUnlock read unlocks endpoint mutex
func (e *Endpoint) RUnlock() {
	e.mutex.RUnlock()
}

// UnconditionalLock should be used only for locking endpoint for
// - setting its state to StateDisconnected
// - handling regular Lock errors
// - reporting endpoint status (like in LogStatus method)
// Use Lock in all other cases
func (e *Endpoint) UnconditionalLock() {
	e.mutex.Lock()
}

// UnconditionalRLock should be used only for reporting endpoint state
func (e *Endpoint) UnconditionalRLock() {
	e.mutex.RLock()
}

// LogDisconnectedMutexAction gets the logger and logs given error with context
func (e *Endpoint) LogDisconnectedMutexAction(err error, context string) {
	e.getLogger().WithError(err).Error(context)
}
