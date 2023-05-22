// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/metrics"
)

const (
	metricAllocate = "allocate"
	metricRelease  = "release"
)

// Error definitions
var (
	// ErrIPv4Disabled is returned when IPv4 allocation is disabled
	ErrIPv4Disabled = errors.New("IPv4 allocation disabled")

	// ErrIPv6Disabled is returned when Ipv6 allocation is disabled
	ErrIPv6Disabled = errors.New("IPv6 allocation disabled")
)

func (ipam *IPAM) determineIPAMPool(owner string) (Pool, error) {
	if ipam.metadata == nil {
		return PoolDefault, nil
	}

	pool, err := ipam.metadata.GetIPPoolForPod(owner)
	if err != nil {
		return "", fmt.Errorf("unable to determine IPAM pool for owner %q: %w", owner, err)
	}

	return Pool(pool), nil
}

// AllocateIP allocates a IP address.
func (ipam *IPAM) AllocateIP(ip net.IP, owner string, pool Pool) error {
	needSyncUpstream := true
	_, err := ipam.allocateIP(ip, owner, pool, needSyncUpstream)
	return err
}

// AllocateIPWithoutSyncUpstream allocates a IP address without syncing upstream.
func (ipam *IPAM) AllocateIPWithoutSyncUpstream(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	needSyncUpstream := false
	return ipam.allocateIP(ip, owner, pool, needSyncUpstream)
}

// AllocateIPString is identical to AllocateIP but takes a string
func (ipam *IPAM) AllocateIPString(ipAddr, owner string, pool Pool) error {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return fmt.Errorf("Invalid IP address: %s", ipAddr)
	}
	return ipam.AllocateIP(ip, owner, pool)
}

func (ipam *IPAM) allocateIP(ip net.IP, owner string, pool Pool, needSyncUpstream bool) (result *AllocationResult, err error) {
	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()

	if pool == "" {
		return nil, fmt.Errorf("unable to restore IP %s for %q: pool name must be provided", ip, owner)
	}

	if ownedBy, ok := ipam.isIPExcluded(ip, pool); ok {
		err = fmt.Errorf("IP %s is excluded, owned by %s", ip, ownedBy)
		return
	}

	family := IPv4
	if ip.To4() != nil {
		if ipam.IPv4Allocator == nil {
			err = ErrIPv4Disabled
			return
		}

		if needSyncUpstream {
			if result, err = ipam.IPv4Allocator.Allocate(ip, owner, pool); err != nil {
				return
			}
		} else {
			if result, err = ipam.IPv4Allocator.AllocateWithoutSyncUpstream(ip, owner, pool); err != nil {
				return
			}
		}
	} else {
		family = IPv6
		if ipam.IPv6Allocator == nil {
			err = ErrIPv6Disabled
			return
		}

		if needSyncUpstream {
			if result, err = ipam.IPv6Allocator.Allocate(ip, owner, pool); err != nil {
				return
			}
		} else {
			if result, err = ipam.IPv6Allocator.AllocateWithoutSyncUpstream(ip, owner, pool); err != nil {
				return
			}
		}
	}

	// If the allocator did not populate the pool, we assume it does not
	// support IPAM pools and assign the default pool instead
	if result.IPPoolName == "" {
		result.IPPoolName = PoolDefault
	}

	log.WithFields(logrus.Fields{
		"ip":    ip.String(),
		"owner": owner,
		"pool":  result.IPPoolName,
	}).Debugf("Allocated specific IP")

	ipam.registerIPOwner(ip, owner, pool)
	metrics.IpamEvent.WithLabelValues(metricAllocate, string(family)).Inc()
	return
}

func (ipam *IPAM) allocateNextFamily(family Family, owner string, pool Pool, needSyncUpstream bool) (result *AllocationResult, err error) {
	var allocator Allocator
	switch family {
	case IPv6:
		allocator = ipam.IPv6Allocator
	case IPv4:
		allocator = ipam.IPv4Allocator

	default:
		err = fmt.Errorf("unknown address \"%s\" family requested", family)
		return
	}

	if allocator == nil {
		err = fmt.Errorf("%s allocator not available", family)
		return
	}

	if pool == "" {
		pool, err = ipam.determineIPAMPool(owner)
		if err != nil {
			return
		}
	}

	for {
		if needSyncUpstream {
			result, err = allocator.AllocateNext(owner, pool)
		} else {
			result, err = allocator.AllocateNextWithoutSyncUpstream(owner, pool)
		}
		if err != nil {
			return
		}

		// If the allocator did not populate the pool, we assume it does not
		// support IPAM pools and assign the default pool instead
		if result.IPPoolName == "" {
			result.IPPoolName = PoolDefault
		}

		if _, ok := ipam.isIPExcluded(result.IP, pool); !ok {
			log.WithFields(logrus.Fields{
				"ip":    result.IP.String(),
				"pool":  result.IPPoolName,
				"owner": owner,
			}).Debugf("Allocated random IP")
			ipam.registerIPOwner(result.IP, owner, pool)
			metrics.IpamEvent.WithLabelValues(metricAllocate, string(family)).Inc()
			return
		}

		// The allocated IP is excluded, do not use it. The excluded IP
		// is now allocated so it won't be allocated in the next
		// iteration.
		ipam.registerIPOwner(result.IP, fmt.Sprintf("%s (excluded)", owner), pool)
	}
}

// AllocateNextFamily allocates the next IP of the requested address family
func (ipam *IPAM) AllocateNextFamily(family Family, owner string, pool Pool) (result *AllocationResult, err error) {
	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()

	needSyncUpstream := true

	return ipam.allocateNextFamily(family, owner, pool, needSyncUpstream)
}

// AllocateNextFamilyWithoutSyncUpstream allocates the next IP of the requested address family
// without syncing upstream
func (ipam *IPAM) AllocateNextFamilyWithoutSyncUpstream(family Family, owner string, pool Pool) (result *AllocationResult, err error) {
	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()

	needSyncUpstream := false

	return ipam.allocateNextFamily(family, owner, pool, needSyncUpstream)
}

// AllocateNext allocates the next available IPv4 and IPv6 address out of the
// configured address pool. If family is set to "ipv4" or "ipv6", then
// allocation is limited to the specified address family. If the pool has been
// drained of addresses, an error will be returned.
func (ipam *IPAM) AllocateNext(family, owner string, pool Pool) (ipv4Result, ipv6Result *AllocationResult, err error) {
	if (family == "ipv6" || family == "") && ipam.IPv6Allocator != nil {
		ipv6Result, err = ipam.AllocateNextFamily(IPv6, owner, pool)
		if err != nil {
			return
		}

	}

	if (family == "ipv4" || family == "") && ipam.IPv4Allocator != nil {
		ipv4Result, err = ipam.AllocateNextFamily(IPv4, owner, pool)
		if err != nil {
			if ipv6Result != nil {
				ipam.ReleaseIP(ipv6Result.IP, ipv6Result.IPPoolName)
			}
			return
		}
	}

	return
}

// AllocateNextWithExpiration is identical to AllocateNext but registers an
// expiration timer as well. This is identical to using AllocateNext() in
// combination with StartExpirationTimer()
func (ipam *IPAM) AllocateNextWithExpiration(family, owner string, pool Pool, timeout time.Duration) (ipv4Result, ipv6Result *AllocationResult, err error) {
	ipv4Result, ipv6Result, err = ipam.AllocateNext(family, owner, pool)
	if err != nil {
		return nil, nil, err
	}

	if timeout != time.Duration(0) {
		for _, result := range []*AllocationResult{ipv4Result, ipv6Result} {
			if result != nil {
				result.ExpirationUUID, err = ipam.StartExpirationTimer(result.IP, pool, timeout)
				if err != nil {
					if ipv4Result != nil {
						ipam.ReleaseIP(ipv4Result.IP, ipv4Result.IPPoolName)
					}
					if ipv6Result != nil {
						ipam.ReleaseIP(ipv6Result.IP, ipv6Result.IPPoolName)
					}
					return
				}
			}
		}
	}

	return
}

func (ipam *IPAM) releaseIPLocked(ip net.IP, pool Pool) error {
	if pool == "" {
		return fmt.Errorf("no IPAM pool provided for IP release of %s", ip)
	}

	family := IPv4
	if ip.To4() != nil {
		if ipam.IPv4Allocator == nil {
			return ErrIPv4Disabled
		}

		ipam.IPv4Allocator.Release(ip, pool)
	} else {
		family = IPv6
		if ipam.IPv6Allocator == nil {
			return ErrIPv6Disabled
		}

		ipam.IPv6Allocator.Release(ip, pool)
	}

	owner := ipam.releaseIPOwner(ip, pool)
	log.WithFields(logrus.Fields{
		"ip":    ip.String(),
		"owner": owner,
	}).Debugf("Released IP")
	delete(ipam.expirationTimers, ip.String())

	metrics.IpamEvent.WithLabelValues(metricRelease, string(family)).Inc()
	return nil
}

// ReleaseIP release a IP address. The pool argument must not be empty, it
// must be set to the pool name returned by the `Allocate*` functions when
// the IP was allocated.
func (ipam *IPAM) ReleaseIP(ip net.IP, pool Pool) error {
	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()
	return ipam.releaseIPLocked(ip, pool)
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
			// XXX: only consider default pool for now
			owner := ipam.getIPOwner(ip, PoolDefault)
			// If owner is not available, report IP but leave owner empty
			allocv4[ip] = owner
		}
	}

	if ipam.IPv6Allocator != nil {
		allocv6, st6 = ipam.IPv6Allocator.Dump()
		st6 = "IPv6: " + st6
		for ip := range allocv6 {
			// XXX: only consider default pool for now
			owner := ipam.getIPOwner(ip, PoolDefault)
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

// StartExpirationTimer installs an expiration timer for a previously allocated
// IP. Unless StopExpirationTimer is called in time, the IP will be released
// again after expiration of the specified timeout. The function will return a
// UUID representing the unique allocation attempt. The same UUID must be
// passed into StopExpirationTimer again.
//
// This function is to be used as allocation and use of an IP can be controlled
// by an external entity and that external entity can disappear. Therefore such
// users should register an expiration timer before returning the IP and then
// stop the expiration timer when the IP has been used.
func (ipam *IPAM) StartExpirationTimer(ip net.IP, pool Pool, timeout time.Duration) (string, error) {
	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()

	ipString := ip.String()
	if _, ok := ipam.expirationTimers[ipString]; ok {
		return "", fmt.Errorf("expiration timer already registered")
	}

	allocationUUID := uuid.New().String()
	ipam.expirationTimers[ipString] = allocationUUID

	go func(ip net.IP, allocationUUID string, timeout time.Duration) {
		ipString := ip.String()
		time.Sleep(timeout)

		ipam.allocatorMutex.Lock()
		defer ipam.allocatorMutex.Unlock()

		if currentUUID, ok := ipam.expirationTimers[ipString]; ok {
			if currentUUID == allocationUUID {
				scopedLog := log.WithFields(logrus.Fields{"ip": ipString, "uuid": allocationUUID})
				if err := ipam.releaseIPLocked(ip, pool); err != nil {
					scopedLog.WithError(err).Warning("Unable to release IP after expiration")
				} else {
					scopedLog.Warning("Released IP after expiration")
				}
			} else {
				// This is an obsolete expiration timer. The IP
				// was reused and a new expiration timer is
				// already attached
			}
		} else {
			// Expiration timer was removed. No action is required
		}
	}(ip, allocationUUID, timeout)

	return allocationUUID, nil
}

// StopExpirationTimer will remove the expiration timer for a particular IP.
// The UUID returned by the symmetric StartExpirationTimer must be provided.
// The expiration timer will only be removed if the UUIDs match. Releasing an
// IP will also stop the expiration timer.
func (ipam *IPAM) StopExpirationTimer(ip net.IP, pool Pool, allocationUUID string) error {
	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()

	ipString := ip.String()
	if currentUUID, ok := ipam.expirationTimers[ipString]; !ok {
		return fmt.Errorf("no expiration timer registered")
	} else if currentUUID != allocationUUID {
		return fmt.Errorf("UUID mismatch, not stopping expiration timer")
	}

	delete(ipam.expirationTimers, ipString)

	return nil
}
