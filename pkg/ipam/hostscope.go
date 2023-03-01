// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"fmt"
	"math/big"
	"net"

	"strings"

	"github.com/cilium/cilium/pkg/k8s/watchers"

	"github.com/cilium/ipam/service/ipallocator"

	"github.com/cilium/cilium/pkg/ip"
)

type hostScopeAllocator struct {
	allocCIDR *net.IPNet
	allocator *ipallocator.Range

	// for k8s lister
	k8swatcher *watchers.K8sWatcher
}

func newHostScopeAllocator(n *net.IPNet, k8sEventReg K8sEventRegister) Allocator {
	cidrRange, err := ipallocator.NewCIDRRange(n)
	if err != nil {
		panic(err)
	}
	a := &hostScopeAllocator{
		allocCIDR: n,
		allocator: cidrRange,
	}
	a.k8swatcher, _ = k8sEventReg.(*watchers.K8sWatcher)

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
	var result AllocationResult
	var err error
	if h.k8swatcher != nil {
		names := strings.Split(owner, "/")
		pod, err := h.k8swatcher.GetCachedPod(names[0], names[1])
		if err != nil {
			return nil, fmt.Errorf("get pod %s info failed %v. ", owner, err)
		}
		if pod.Annotations != nil {
			if pod.Annotations[customPodIpAddr] != "" {
				result.IP = net.ParseIP(pod.Annotations[customPodIpAddr])
				if result.IP == nil {
					return nil, fmt.Errorf("customer invalid ip: %s. ", pod.Annotations[customPodIpAddr])
				}
				err = h.allocator.Allocate(result.IP)
				if err != nil {
					return nil, fmt.Errorf("customer ip is not avaliable %s: %w", result.IP.String(), err)
				}
				return &result, nil
			}
		}
	}

	result.IP, err = h.allocator.AllocateNext()
	if err != nil {
		return nil, err
	}
	return &result, nil
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
