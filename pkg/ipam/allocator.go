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
	"net"
	"strings"

	"github.com/cilium/cilium/pkg/metrics"

	"github.com/sirupsen/logrus"
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

// AllocateIP allocates a IP address.
func (ipam *IPAM) AllocateIP(ip net.IP, owner string) error {
	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()

	if ipam.blacklist.Contains(ip) {
		return fmt.Errorf("IP %s is blacklisted, owned by %s", ip.String(), owner)
	}

	family := familyIPv4
	if ip.To4() != nil {
		if ipam.IPv4Allocator == nil {
			return ErrIPv4Disabled
		}

		if err := ipam.IPv4Allocator.Allocate(ip, owner); err != nil {
			return err
		}
	} else {
		family = familyIPv6
		if ipam.IPv6Allocator == nil {
			return ErrIPv6Disabled
		}

		if err := ipam.IPv6Allocator.Allocate(ip, owner); err != nil {
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

func (ipam *IPAM) allocateNextFamily(family Family, allocator Allocator, owner string) (ip net.IP, err error) {
	if allocator == nil {
		return nil, fmt.Errorf("%s allocator not available", family)
	}

	for {
		ip, err = allocator.AllocateNext(owner)
		if err != nil {
			return
		}

		if !ipam.blacklist.Contains(ip) {
			log.WithFields(logrus.Fields{
				"ip":    ip.String(),
				"owner": owner,
			}).Debugf("Allocated random IP")
			ipam.owner[ip.String()] = owner
			metrics.IpamEvent.WithLabelValues(metricAllocate, string(family)).Inc()
			return
		}

		// The allocated IP is blacklisted, do not use it. The
		// blacklisted IP is now allocated so it won't be allocated in
		// the next iteration.
		ipam.owner[ip.String()] = fmt.Sprintf("%s (blacklisted)", owner)
	}
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

// ReleaseIPString is identical to ReleaseIP but takes a string
func (ipam *IPAM) ReleaseIPString(ipAddr string) error {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return fmt.Errorf("Invalid IP address: %s", ipAddr)
	}

	return ipam.ReleaseIP(ip)
}

// Dump dumps the list of allocated IP addresses
func (ipam *IPAM) Dump() (allocv4 map[string]string, allocv6 map[string]string, status string) {
	var st4, st6 string

	ipam.allocatorMutex.RLock()
	defer ipam.allocatorMutex.RUnlock()

	if ipam.IPv4Allocator != nil {
		allocv4, st4 = ipam.IPv4Allocator.Dump()
		st4 = "IPv4: " + st4
		for ip := range allocv4 {
			owner, _ := ipam.owner[ip]
			// If owner is not available, report IP but leave owner empty
			allocv4[ip] = owner
		}
	}

	if ipam.IPv6Allocator != nil {
		allocv6, st6 = ipam.IPv6Allocator.Dump()
		st6 = "IPv6: " + st6
		for ip := range allocv6 {
			owner, _ := ipam.owner[ip]
			// If owner is not available, report IP but leave owner empty
			allocv6[ip] = owner
		}
	}

	status = strings.Join([]string{st4, st6}, ", ")
	if status == "" {
		status = "Not running"
	}

	return
}
