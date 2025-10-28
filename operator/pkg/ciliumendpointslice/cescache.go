// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

type CESCache struct {
}

// Creates and intializes the new CESCache
func newCESCache() *CESCache {
	return &CESCache{}
}
