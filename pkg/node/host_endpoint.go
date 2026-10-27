// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"sync"
	"sync/atomic"
)

const (
	templateHostEndpointID = uint64(0xffff)
)

var endpointID atomic.Uint64

// endpointIDWatchMu serializes updates with read-and-subscribe operations so
// consumers cannot miss an ID change between reading the ID and watching it.
var endpointIDWatchMu sync.Mutex
var endpointIDChanged = make(chan struct{})

func init() {
	endpointID.Store(templateHostEndpointID)
}

// GetEndpointID returns the ID of the host endpoint for this node.
// The boolean return value indicates whether the host endpoint ID
// has been set (true) or is still the uninitialized template value (false).
func GetEndpointID() (uint64, bool) {
	id := endpointID.Load()
	return id, id != templateHostEndpointID
}

// GetEndpointIDAndWatch returns the host endpoint ID, whether it has been
// initialized, and a channel that closes when the ID changes. The ID and watch
// are acquired atomically with respect to SetEndpointID.
func GetEndpointIDAndWatch() (uint64, bool, <-chan struct{}) {
	endpointIDWatchMu.Lock()
	defer endpointIDWatchMu.Unlock()

	id, initialized := GetEndpointID()
	return id, initialized, endpointIDChanged
}

// SetEndpointID sets the ID of the host endpoint for this node.
func SetEndpointID(id uint64) {
	endpointIDWatchMu.Lock()
	defer endpointIDWatchMu.Unlock()

	if endpointID.Load() == id {
		return
	}
	endpointID.Store(id)
	close(endpointIDChanged)
	endpointIDChanged = make(chan struct{})
}
