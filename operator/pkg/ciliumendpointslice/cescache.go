// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

// CESCache stores local CES goal state when the CES controller is running in slim mode.
type CESCache struct {
}

// Creates and intializes the new CESCache
func newCESCache() *CESCache {
	return &CESCache{}
}
