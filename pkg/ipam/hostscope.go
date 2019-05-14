// Copyright 2017-2019 Authors of Cilium
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

	k8sAPI "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/registry/core/service/ipallocator"
)

type hostScopeAllocator struct {
	allocCIDR *net.IPNet
	allocator *ipallocator.Range
}

func newHostScopeAllocator(n *net.IPNet) Allocator {
	a := &hostScopeAllocator{
		allocCIDR: n,
		allocator: ipallocator.NewCIDRRange(n),
	}

	return a
}

func (h *hostScopeAllocator) Allocate(ip net.IP, owner string) error {
	return h.allocator.Allocate(ip)
}

func (h *hostScopeAllocator) Release(ip net.IP) error {
	return h.allocator.Release(ip)
}

func (h *hostScopeAllocator) AllocateNext(owner string) (net.IP, error) {
	return h.allocator.AllocateNext()
}

func (h *hostScopeAllocator) Dump() (map[string]string, string) {
	alloc := map[string]string{}
	ral := k8sAPI.RangeAllocation{}
	h.allocator.Snapshot(&ral)
	origIP := big.NewInt(0).SetBytes(h.allocCIDR.IP.To4())
	bits := big.NewInt(0).SetBytes(ral.Data)
	for i := 0; i < bits.BitLen(); i++ {
		if bits.Bit(i) != 0 {
			ip := net.IP(big.NewInt(0).Add(origIP, big.NewInt(int64(uint(i+1)))).Bytes()).String()
			alloc[ip] = ""
		}
	}

	maxIPs := ip.CountIPsInCIDR(h.allocCIDR)
	status := fmt.Sprintf("%d/%d allocated from %s", len(alloc), maxIPs, h.allocCIDR.String())

	return alloc, status
}
