// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import "fmt"

var (
	ErrEndpointDeleted = fmt.Errorf("lock failed: endpoint is in the process of being removed")
)

// lockAlive returns error if endpoint was removed, locks underlying mutex otherwise
func (e *Endpoint) lockAlive() error {
	e.mutex.Lock()
	if e.IsDisconnecting() {
		e.mutex.Unlock()
		return ErrEndpointDeleted
	}
	return nil
}

// Unlock unlocks endpoint mutex
func (e *Endpoint) unlock() {
	e.mutex.Unlock()
}

// rlockAlive returns error if endpoint was removed, read locks underlying mutex otherwise
func (e *Endpoint) rlockAlive() error {
	e.mutex.RLock()
	if e.IsDisconnecting() {
		e.mutex.RUnlock()
		return ErrNotAlive
	}
	return nil
}

// runlock read unlocks endpoint mutex
func (e *Endpoint) runlock() {
	e.mutex.RUnlock()
}

// unconditionalLock should be used only for locking endpoint for
// - setting its state to StateDisconnected
// - handling regular Lock errors
// - reporting endpoint status (like in LogStatus method)
// Use Lock in all other cases
func (e *Endpoint) unconditionalLock() {
	e.mutex.Lock()
}

// unconditionalRLock should be used only for reporting endpoint state
func (e *Endpoint) unconditionalRLock() {
	e.mutex.RLock()
}

// logDisconnectedMutexAction gets the logger and logs given error with context
func (e *Endpoint) logDisconnectedMutexAction(err error, context string) {
	e.getLogger().WithError(err).Debug(context)
}
