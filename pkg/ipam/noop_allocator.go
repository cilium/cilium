// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"net"
)

var errNotSupported = errors.New("Operation not supported")

// noOpAllocator implements ipam.Allocator with no-op behavior.
// It is used for IPAMDelegatedPlugin, where the CNI binary is responsible for assigning IPs
// without relying on the cilium daemon or operator.
type noOpAllocator struct{}

func (n *noOpAllocator) Allocate(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	return nil, errNotSupported
}

func (n *noOpAllocator) AllocateWithoutSyncUpstream(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	return nil, errNotSupported
}

func (n *noOpAllocator) Release(ip net.IP, pool Pool) error {
	return errNotSupported
}

func (n *noOpAllocator) AllocateNext(owner string, pool Pool) (*AllocationResult, error) {
	return nil, errNotSupported
}

func (n *noOpAllocator) AllocateNextWithoutSyncUpstream(owner string, pool Pool) (*AllocationResult, error) {
	return nil, errNotSupported
}

func (n *noOpAllocator) Dump() (map[string]string, string) {
	return nil, "delegated to plugin"
}

func (n *noOpAllocator) RestoreFinished() {
}
