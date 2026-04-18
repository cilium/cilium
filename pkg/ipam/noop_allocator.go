// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"net/netip"
)

var errNotSupported = errors.New("Operation not supported")

// noOpAllocator implements ipam.Allocator with no-op behavior.
// It is used for IPAMDelegatedPlugin, where the CNI binary is responsible for assigning IPs
// without relying on the cilium daemon or operator.
type noOpAllocator struct{}

func (n *noOpAllocator) Allocate(addr netip.Addr, owner string, pool Pool) (*AllocationResult, error) {
	return nil, errNotSupported
}

func (n *noOpAllocator) AllocateWithoutSyncUpstream(addr netip.Addr, owner string, pool Pool) (*AllocationResult, error) {
	return nil, errNotSupported
}

func (n *noOpAllocator) Release(addr netip.Addr, pool Pool) error {
	return errNotSupported
}

func (n *noOpAllocator) AllocateNext(owner string, pool Pool) (*AllocationResult, error) {
	return nil, errNotSupported
}

func (n *noOpAllocator) AllocateNextWithoutSyncUpstream(owner string, pool Pool) (*AllocationResult, error) {
	return nil, errNotSupported
}

func (n *noOpAllocator) Dump() (map[Pool]map[string]string, string) {
	return nil, "delegated to plugin"
}

func (n *noOpAllocator) Capacity() uint64 {
	return uint64(0)
}

func (n *noOpAllocator) RestoreFinished() {
}
