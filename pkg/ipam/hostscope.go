// Copyright 2017-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipam

import (
	"fmt"
	"math/big"
	"net"

	"github.com/cilium/cilium/pkg/ip"

	"github.com/cilium/ipam/service/ipallocator"
)

type hostScopeAllocator struct {
	allocCIDR *net.IPNet
	allocator *ipallocator.Range
}

func newHostScopeAllocator(n *net.IPNet) Allocator {
	cidrRange, err := ipallocator.NewCIDRRange(n)
	if err != nil {
		panic(err)
	}
	a := &hostScopeAllocator{
		allocCIDR: n,
		allocator: cidrRange,
	}

	return a
}

func (h *hostScopeAllocator) Allocate(ip net.IP, owner string) (*AllocationResult, error) {
	if err := h.allocator.Allocate(ip); err != nil {
		return nil, err
	}

	return &AllocationResult{IP: ip}, nil
}

func (h *hostScopeAllocator) AllocateWithoutSyncUpstream(ip net.IP, owner string) (*AllocationResult, error) {
	if err := h.allocator.Allocate(ip); err != nil {
		return nil, err
	}

	return &AllocationResult{IP: ip}, nil
}

func (h *hostScopeAllocator) Release(ip net.IP) error {
	return h.allocator.Release(ip)
}

func (h *hostScopeAllocator) AllocateNext(owner string) (*AllocationResult, error) {
	ip, err := h.allocator.AllocateNext()
	if err != nil {
		return nil, err
	}

	return &AllocationResult{IP: ip}, nil
}

func (h *hostScopeAllocator) AllocateNextWithoutSyncUpstream(owner string) (*AllocationResult, error) {
	ip, err := h.allocator.AllocateNext()
	if err != nil {
		return nil, err
	}

	return &AllocationResult{IP: ip}, nil
}

func (h *hostScopeAllocator) Dump() (map[string]string, string) {
	var origIP *big.Int
	alloc := map[string]string{}
	_, data, err := h.allocator.Snapshot()
	if err != nil {
		return nil, "Unable to get a snapshot of the allocator"
	}
	if h.allocCIDR.IP.To4() != nil {
		origIP = big.NewInt(0).SetBytes(h.allocCIDR.IP.To4())
	} else {
		origIP = big.NewInt(0).SetBytes(h.allocCIDR.IP.To16())
	}
	bits := big.NewInt(0).SetBytes(data)
	for i := 0; i < bits.BitLen(); i++ {
		if bits.Bit(i) != 0 {
			ip := net.IP(big.NewInt(0).Add(origIP, big.NewInt(int64(uint(i+1)))).Bytes()).String()
			alloc[ip] = ""
		}
	}

	maxIPs := ip.CountIPsInCIDR(h.allocCIDR)
	status := fmt.Sprintf("%d/%s allocated from %s", len(alloc), maxIPs.String(), h.allocCIDR.String())

	return alloc, status
}

// RestoreFinished marks the status of restoration as done
func (h *hostScopeAllocator) RestoreFinished() {}
