// Copyright 2016-2017 Authors of Cilium
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
	"errors"
	"fmt"
	"math/big"
	"net"

	"github.com/cilium/cilium/pkg/metrics"

	k8sAPI "k8s.io/kubernetes/pkg/apis/core"
)

const (
	metricAllocate = "allocate"
	metricRelease  = "release"
	familyIPv4     = "ipv4"
	familyIPv6     = "ipv6"
)

// Error definitions
var (
	// ErrIPv4Disabled is returned when IPv4 allocation is disabled
	ErrIPv4Disabled = errors.New("IPv4 allocation disabled")

	// ErrIPv6Disabled is returned when Ipv6 allocation is disabled
	ErrIPv6Disabled = errors.New("IPv6 allocation disabled")
)

// AllocateIP allocates a IP address.
func (ipam *IPAM) AllocateIP(ip net.IP) error {
	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()
	family := familyIPv4
	if ip.To4() != nil {
		if ipam.IPv4Allocator == nil {
			return ErrIPv4Disabled
		}

		if err := ipam.IPv4Allocator.Allocate(ip); err != nil {
			return err
		}
	} else {
		family = familyIPv6
		if ipam.IPv6Allocator == nil {
			return ErrIPv6Disabled
		}

		if err := ipam.IPv6Allocator.Allocate(ip); err != nil {
			return err
		}
	}

	metrics.IpamEvent.WithLabelValues(metricAllocate, family).Inc()
	return nil
}

// AllocateIPString is identical to AllocateIP but takes a string
func (ipam *IPAM) AllocateIPString(ipAddr string) error {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return fmt.Errorf("Invalid IP address: %s", ipAddr)
	}

	return ipam.AllocateIP(ip)
}

// AllocateNext allocates the next available IPv4 and IPv6 address out of the
// configured address pool. If family is set to "ipv4" or "ipv6", then
// allocation is limited to the specified address family. If the pool has been
// drained of addresses, an error will be returned.
func (ipam *IPAM) AllocateNext(family string) (net.IP, net.IP, error) {
	var ipv4, ipv6 net.IP

	if (family == "ipv6" || family == "") && ipam.IPv6Allocator != nil {
		ipConf, err := ipam.IPv6Allocator.AllocateNext()
		if err != nil {
			return nil, nil, err
		}

		ipv6 = ipConf
		metrics.IpamEvent.WithLabelValues(metricAllocate, familyIPv6).Inc()
	}

	if (family == "ipv4" || family == "") && ipam.IPv4Allocator != nil {
		ipConf, err := ipam.IPv4Allocator.AllocateNext()
		if err != nil {
			if ipv6 != nil {
				ipam.IPv6Allocator.Release(ipv6)
			}
			return nil, nil, err
		}

		ipv4 = ipConf
		metrics.IpamEvent.WithLabelValues(metricAllocate, familyIPv4).Inc()
	}

	return ipv4, ipv6, nil
}

// ReleaseIP release a IP address.
func (ipam *IPAM) ReleaseIP(ip net.IP) error {
	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()
	family := familyIPv4
	if ip.To4() != nil {
		if ipam.IPv4Allocator == nil {
			return ErrIPv4Disabled
		}

		if err := ipam.IPv4Allocator.Release(ip); err != nil {
			return err
		}
	} else {
		family = familyIPv6
		if ipam.IPv6Allocator == nil {
			return ErrIPv6Disabled
		}

		if err := ipam.IPv6Allocator.Release(ip); err != nil {
			return err
		}
	}
	metrics.IpamEvent.WithLabelValues(metricRelease, family).Inc()
	return nil
}

// ReleaseIPString is identical to ReleaseIP but takes a string
func (ipam *IPAM) ReleaseIPString(ipAddr string) error {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return fmt.Errorf("Invalid IP address: %s", ipAddr)
	}

	return ipam.ReleaseIP(ip)
}

// Dump dumps the list of allocated IP addresses
func (ipam *IPAM) Dump() ([]string, []string) {
	ipam.allocatorMutex.RLock()
	defer ipam.allocatorMutex.RUnlock()

	allocv4 := []string{}
	ralv4 := k8sAPI.RangeAllocation{}
	if ipam.IPv4Allocator != nil {
		ipam.IPv4Allocator.Snapshot(&ralv4)
		origIP := big.NewInt(0).SetBytes(ipam.nodeAddressing.IPv4().AllocationCIDR().IP.To4())
		v4Bits := big.NewInt(0).SetBytes(ralv4.Data)
		for i := 0; i < v4Bits.BitLen(); i++ {
			if v4Bits.Bit(i) != 0 {
				allocv4 = append(allocv4, net.IP(big.NewInt(0).Add(origIP, big.NewInt(int64(uint(i+1)))).Bytes()).String())
			}
		}
	}

	allocv6 := []string{}
	ralv6 := k8sAPI.RangeAllocation{}
	if ipam.IPv6Allocator != nil {
		ipam.IPv6Allocator.Snapshot(&ralv6)
		origIP := big.NewInt(0).SetBytes(ipam.nodeAddressing.IPv6().AllocationCIDR().IP)
		v6Bits := big.NewInt(0).SetBytes(ralv6.Data)
		for i := 0; i < v6Bits.BitLen(); i++ {
			if v6Bits.Bit(i) != 0 {
				allocv6 = append(allocv6, net.IP(big.NewInt(0).Add(origIP, big.NewInt(int64(uint(i+1)))).Bytes()).String())
			}
		}
	}

	return allocv4, allocv6
}
