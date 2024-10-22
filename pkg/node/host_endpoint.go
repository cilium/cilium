// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

const (
	templateHostEndpointID = uint64(0xffff)
)

var (
	endpointID = templateHostEndpointID
)

// GetEndpointID returns the ID of the host endpoint for this node.
func GetEndpointID() uint64 {
	return endpointID
}

// SetEndpointID sets the ID of the host endpoint this node.
func SetEndpointID(id uint64) {
	endpointID = id
}
