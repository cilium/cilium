// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import "sync/atomic"

const (
	templateHostEndpointID = uint64(0xffff)
)

var endpointID atomic.Uint64

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

// SetEndpointID sets the ID of the host endpoint for this node.
func SetEndpointID(id uint64) {
	endpointID.Store(id)
}
