// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package node

const (
	templateHostEndpointID = uint64(0xffff)
)

var (
	labels     map[string]string
	endpointID = templateHostEndpointID
)

// GetLabels returns the labels of this node.
func GetLabels() map[string]string {
	return labels
}

// SetLabels sets the labels of this node.
func SetLabels(l map[string]string) {
	labels = l
}

// GetEndpointID returns the ID of the host endpoint for this node.
func GetEndpointID() uint64 {
	return endpointID
}

// SetLabels sets the ID of the host endpoint this node.
func SetEndpointID(id uint64) {
	endpointID = id
}
