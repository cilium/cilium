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

	"github.com/sirupsen/logrus"
	k8sAPI "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/registry/core/service/ipallocator"
)

const (
	metricAllocate = "allocate"
	metricRelease  = "release"
	familyIPv4     = "ipv4"
	familyIPv6     = "ipv6"
)

type owner string

// Error definitions
var (
	// ErrIPv4Disabled is returned when IPv4 allocation is disabled
	ErrIPv4Disabled = errors.New("IPv4 allocation disabled")

	// ErrIPv6Disabled is returned when Ipv6 allocation is disabled
	ErrIPv6Disabled = errors.New("IPv6 allocation disabled")
)

func (ipam *IPAM) lookupIPsByOwner(owner string) (ips []net.IP) {
	ipam.allocatorMutex.RLock()
	defer ipam.allocatorMutex.RUnlock()

	for ip, o := range ipam.owner {
		if o == owner {
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				ips = append(ips, parsedIP)
			}
		}
	}

	return
}

// AllocateIP allocates a IP address.
func (ipam *IPAM) AllocateIP(ip net.IP, owner string) error {
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

	log.WithFields(logrus.Fields{
		"ip":    ip.String(),
		"owner": owner,
	}).Debugf("Allocated specific IP")

	ipam.owner[ip.String()] = owner
	metrics.IpamEvent.WithLabelValues(metricAllocate, family).Inc()
	return nil
}

// AllocateIPString is identical to AllocateIP but takes a string
func (ipam *IPAM) AllocateIPString(ipAddr, owner string) error {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return fmt.Errorf("Invalid IP address: %s", ipAddr)
	}

	return ipam.AllocateIP(ip, owner)
}

func (ipam *IPAM) allocateNextFamily(family Family, allocator *ipallocator.Range, owner string) (ip net.IP, err error) {
	if allocator == nil {
		return nil, fmt.Errorf("%s allocator not available", family)
	}

	ip, err = allocator.AllocateNext()
	if err == nil {
		log.WithFields(logrus.Fields{
			"ip":    ip.String(),
			"owner": owner,
		}).Debugf("Allocated random IP")
		ipam.owner[ip.String()] = owner
		metrics.IpamEvent.WithLabelValues(metricAllocate, string(family)).Inc()
	}

	return
}

// AllocateNextFamily allocates the next IP of the requested address family
func (ipam *IPAM) AllocateNextFamily(family Family, owner string) (ip net.IP, err error) {
	switch family {
	case IPv6:
		ip, err = ipam.allocateNextFamily(family, ipam.IPv6Allocator, owner)
	case IPv4:
		ip, err = ipam.allocateNextFamily(family, ipam.IPv4Allocator, owner)

	default:
		err = fmt.Errorf("unknown address \"%s\" family requested", family)
	}
	return
}

// AllocateNext allocates the next available IPv4 and IPv6 address out of the
// configured address pool. If family is set to "ipv4" or "ipv6", then
// allocation is limited to the specified address family. If the pool has been
// drained of addresses, an error will be returned.
func (ipam *IPAM) AllocateNext(family, owner string) (ipv4 net.IP, ipv6 net.IP, err error) {
	if (family == "ipv6" || family == "") && ipam.IPv6Allocator != nil {
		ipv6, err = ipam.AllocateNextFamily(IPv6, owner)
		if err != nil {
			return
		}

	}

	if (family == "ipv4" || family == "") && ipam.IPv4Allocator != nil {
		ipv4, err = ipam.AllocateNextFamily(IPv4, owner)
		if err != nil {
			if ipv6 != nil {
				ipam.ReleaseIP(ipv6)
			}
			return
		}
	}

	return
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

	owner := ipam.owner[ip.String()]
	log.WithFields(logrus.Fields{
		"ip":    ip.String(),
		"owner": owner,
	}).Debugf("Released IP")
	delete(ipam.owner, ip.String())

	metrics.IpamEvent.WithLabelValues(metricRelease, family).Inc()
	return nil
}

// ReleaseIPString is identical to ReleaseIP but takes a string and supports
// referring to the IPs to be released with the IP itself or the owner name
// used during allocation. If the owner can be referred to multiple IPs, then
// all IPs are being released.
func (ipam *IPAM) ReleaseIPString(releaseArg string) (err error) {
	var ips []net.IP

	ip := net.ParseIP(releaseArg)
	if ip == nil {
		ips = ipam.lookupIPsByOwner(releaseArg)
		if len(ips) == 0 {
			return fmt.Errorf("Invalid IP address or owner name: %s", releaseArg)
		}
	} else {
		ips = append(ips, ip)
	}

	for _, parsedIP := range ips {
		// If any of the releases fail, report the failure
		if err2 := ipam.ReleaseIP(parsedIP); err2 != nil {
			err = err2
		}
	}
	return
}

// Dump dumps the list of allocated IP addresses
func (ipam *IPAM) Dump() (map[string]string, map[string]string) {
	ipam.allocatorMutex.RLock()
	defer ipam.allocatorMutex.RUnlock()

	allocv4 := map[string]string{}
	ralv4 := k8sAPI.RangeAllocation{}
	if ipam.IPv4Allocator != nil {
		ipam.IPv4Allocator.Snapshot(&ralv4)
		origIP := big.NewInt(0).SetBytes(ipam.nodeAddressing.IPv4().AllocationCIDR().IP.To4())
		v4Bits := big.NewInt(0).SetBytes(ralv4.Data)
		for i := 0; i < v4Bits.BitLen(); i++ {
			if v4Bits.Bit(i) != 0 {
				ip := net.IP(big.NewInt(0).Add(origIP, big.NewInt(int64(uint(i+1)))).Bytes()).String()
				owner, _ := ipam.owner[ip]
				// If owner is not available, report IP but leave owner empty
				allocv4[ip] = owner
			}
		}
	}

	allocv6 := map[string]string{}
	ralv6 := k8sAPI.RangeAllocation{}
	if ipam.IPv6Allocator != nil {
		ipam.IPv6Allocator.Snapshot(&ralv6)
		origIP := big.NewInt(0).SetBytes(ipam.nodeAddressing.IPv6().AllocationCIDR().IP)
		v6Bits := big.NewInt(0).SetBytes(ralv6.Data)
		for i := 0; i < v6Bits.BitLen(); i++ {
			if v6Bits.Bit(i) != 0 {
				ip := net.IP(big.NewInt(0).Add(origIP, big.NewInt(int64(uint(i+1)))).Bytes()).String()
				owner, _ := ipam.owner[ip]
				// If owner is not available, report IP but leave owner empty
				allocv6[ip] = owner
			}
		}
	}

	return allocv4, allocv6
}
