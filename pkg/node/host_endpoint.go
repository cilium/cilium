// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package node

import (
	"github.com/cilium/cilium/pkg/lock"
)

const (
	templateHostEndpointID = uint64(0xffff)
)

var (
	labels     map[string]string
	labelsMu   lock.RWMutex
	endpointID = templateHostEndpointID
)

// GetLabels returns the labels of this node.
func GetLabels() map[string]string {
	labelsMu.RLock()
	defer labelsMu.RUnlock()
	return labels
}

// SetLabels sets the labels of this node.
func SetLabels(l map[string]string) {
	labelsMu.Lock()
	defer labelsMu.Unlock()
	labels = l
}

// GetEndpointID returns the ID of the host endpoint for this node.
func GetEndpointID() uint64 {
	return endpointID
}

// SetEndpointID sets the ID of the host endpoint this node.
func SetEndpointID(id uint64) {
	endpointID = id
}
