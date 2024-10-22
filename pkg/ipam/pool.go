// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
	"github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// A podCIDRPool manages the allocation of IPs in multiple pod CIDRs.
// It maintains one IP allocator for each pod CIDR in the pool.
// Unused pod CIDRs which have been marked as released, but not yet deleted
// from the local CiliumNode CRD by the operator are put into the released set.
// Once the operator removes a released pod CIDR from the CiliumNode CRD spec,
// it is also deleted from the release set.
// Pod CIDRs which have been erroneously deleted from the CiliumNode CRD spec
// (either by a buggy operator or by manual/human changes CRD) are marked in
// the removed map. If IP addresses have been allocated from such a pod CIDR,
// its allocator is kept around. But no new IPs will be allocated from this
// pod CIDR. By keeping removed CIDRs in the CiliumNode CRD status, we indicate
// to the operator that we would like to re-gain ownership over that pod CIDR.
type podCIDRPool struct {
	mutex        lock.Mutex
	ipAllocators []*ipallocator.Range
	released     map[string]struct{} // key is a CIDR string, e.g. 10.20.30.0/24
	removed      map[string]struct{} // key is a CIDR string, e.g. 10.20.30.0/24
}

// newPodCIDRPool creates a new pod CIDR pool.
func newPodCIDRPool() *podCIDRPool {
	return &podCIDRPool{
		released: map[string]struct{}{},
		removed:  map[string]struct{}{},
	}
}

func (p *podCIDRPool) allocate(ip net.IP) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, ipAllocator := range p.ipAllocators {
		cidrNet := ipAllocator.CIDR()
		if cidrNet.Contains(ip) {
			return ipAllocator.Allocate(ip)
		}
	}

	return fmt.Errorf("IP %s not in range of any pod CIDR", ip)
}

func (p *podCIDRPool) allocateNext() (net.IP, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// When allocating a random IP, we try the pod CIDRs in the order they are
	// listed in the CRD. This avoids internal fragmentation.
	for _, ipAllocator := range p.ipAllocators {
		cidrNet := ipAllocator.CIDR()
		cidrStr := cidrNet.String()
		if _, removed := p.removed[cidrStr]; removed {
			continue
		}
		if ipAllocator.Free() == 0 {
			continue
		}
		return ipAllocator.AllocateNext()
	}

	return nil, errors.New("all pod CIDR ranges are exhausted")
}

func (p *podCIDRPool) release(ip net.IP) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, ipAllocator := range p.ipAllocators {
		cidrNet := ipAllocator.CIDR()
		if cidrNet.Contains(ip) {
			ipAllocator.Release(ip)
			return
		}
	}
}

func (p *podCIDRPool) hasAvailableIPs() bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, ipAllocator := range p.ipAllocators {
		cidrNet := ipAllocator.CIDR()
		cidrStr := cidrNet.String()
		if _, removed := p.removed[cidrStr]; removed {
			continue
		}
		if ipAllocator.Free() > 0 {
			return true
		}
	}

	return false
}

func (p *podCIDRPool) inUseIPCount() (count int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, ipAllocator := range p.ipAllocators {
		count += ipAllocator.Used()
	}
	return count
}

func (p *podCIDRPool) inUsePodCIDRs() []types.IPAMPodCIDR {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.inUsePodCIDRsLocked()
}

func (p *podCIDRPool) inUsePodCIDRsLocked() []types.IPAMPodCIDR {
	podCIDRs := make([]types.IPAMPodCIDR, 0, len(p.ipAllocators))
	for _, ipAllocator := range p.ipAllocators {
		ipnet := ipAllocator.CIDR()
		podCIDRs = append(podCIDRs, types.IPAMPodCIDR(ipnet.String()))
	}
	return podCIDRs
}

func (p *podCIDRPool) dump() (ipToOwner map[string]string, usedIPs, freeIPs, numPodCIDRs int, err error) {
	// TODO(gandro): Use the Snapshot interface to avoid locking during dump
	p.mutex.Lock()
	defer p.mutex.Unlock()

	ipToOwner = map[string]string{}
	for _, ipAllocator := range p.ipAllocators {
		cidrNet := ipAllocator.CIDR()
		cidrStr := cidrNet.String()
		usedIPs += ipAllocator.Used()
		if _, removed := p.removed[cidrStr]; !removed {
			freeIPs += ipAllocator.Free()
		}
		ipAllocator.ForEach(func(ip net.IP) {
			ipToOwner[ip.String()] = ""
		})
	}
	numPodCIDRs = len(p.ipAllocators)

	return
}

func (p *podCIDRPool) capacity() (freeIPs int) {
	// TODO(gandro): Use the Snapshot interface to avoid locking during dump
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, ipAllocator := range p.ipAllocators {
		cidrNet := ipAllocator.CIDR()
		cidrStr := cidrNet.String()
		if _, removed := p.removed[cidrStr]; !removed {
			freeIPs += ipAllocator.Free()
		}
	}

	return
}

// releaseExcessCIDRsMultiPool implements the logic for multi-pool IPAM
func (p *podCIDRPool) releaseExcessCIDRsMultiPool(neededIPs int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	totalFree := 0
	for _, ipAllocator := range p.ipAllocators {
		totalFree += ipAllocator.Free()
	}

	// Iterate over pod CIDRs in reverse order, so we prioritize releasing
	// later pod CIDRs.
	retainedAllocators := []*ipallocator.Range{}
	for i := len(p.ipAllocators) - 1; i >= 0; i-- {
		ipAllocator := p.ipAllocators[i]
		cidrNet := ipAllocator.CIDR()
		cidrStr := cidrNet.String()

		// If the pod CIDR is not used and releasing it would
		// not take us below the release threshold, then release it immediately
		free := ipAllocator.Free()
		if ipAllocator.Used() == 0 && totalFree-free >= neededIPs {
			p.released[cidrStr] = struct{}{}
			totalFree -= free
			log.WithField(logfields.CIDR, cidrStr).Debug("releasing pod CIDR")
		} else {
			retainedAllocators = append(retainedAllocators, ipAllocator)
		}
	}

	p.ipAllocators = retainedAllocators
}

func (p *podCIDRPool) updatePool(podCIDRs []string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if option.Config.Debug {
		log.WithFields(logrus.Fields{
			logfields.NewCIDR: podCIDRs,
			logfields.OldCIDR: p.inUsePodCIDRsLocked(),
		}).Debug("Updating IPAM pool")
	}

	// Parse the pod CIDRs, ignoring invalid CIDRs, and de-duplicating them.
	cidrNets := make([]*net.IPNet, 0, len(podCIDRs))
	cidrStrSet := make(map[string]struct{}, len(podCIDRs))
	for _, podCIDR := range podCIDRs {
		_, cidr, err := net.ParseCIDR(podCIDR)
		if err != nil {
			log.WithError(err).WithField(logfields.CIDR, podCIDR).Error("ignoring invalid pod CIDR")
			continue
		}
		if _, ok := cidrStrSet[cidr.String()]; ok {
			log.WithField(logfields.CIDR, podCIDR).Error("ignoring duplicate pod CIDR")
			continue
		}
		cidrNets = append(cidrNets, cidr)
		cidrStrSet[cidr.String()] = struct{}{}
	}

	// Forget any released pod CIDRs no longer present in the CRD.
	for cidrStr := range p.released {
		if _, ok := cidrStrSet[cidrStr]; !ok {
			log.WithField(logfields.CIDR, cidrStr).Debug("removing released pod CIDR")
			delete(p.released, cidrStr)
		}

		if option.Config.EnableUnreachableRoutes {
			if err := cleanupUnreachableRoutes(cidrStr); err != nil {
				log.WithFields(logrus.Fields{
					logfields.CIDR:  cidrStr,
					logrus.ErrorKey: err,
				}).Warning("failed to remove unreachable routes for pod cidr")
			}
		}
	}

	// newIPAllocators is the new slice of IP allocators.
	newIPAllocators := make([]*ipallocator.Range, 0, len(podCIDRs))

	// addedCIDRs is the set of pod CIDRs that have a corresponding allocator
	existingAllocators := make(map[string]struct{}, len(p.ipAllocators))

	// Add existing IP allocators to newIPAllocators in order.
	for _, ipAllocator := range p.ipAllocators {
		cidrNet := ipAllocator.CIDR()
		cidrStr := cidrNet.String()
		if _, ok := cidrStrSet[cidrStr]; !ok {
			if ipAllocator.Used() == 0 {
				continue
			}
			log.WithField(logfields.CIDR, cidrStr).Error("in-use pod CIDR was removed from spec")
			p.removed[cidrStr] = struct{}{}
		}
		newIPAllocators = append(newIPAllocators, ipAllocator)
		existingAllocators[cidrStr] = struct{}{}
	}

	// Create and add new IP allocators to newIPAllocators.
	for _, cidrNet := range cidrNets {
		cidrStr := cidrNet.String()
		if _, ok := existingAllocators[cidrStr]; ok {
			continue
		}
		ipAllocator := ipallocator.NewCIDRRange(cidrNet)
		if ipAllocator.Free() == 0 {
			log.WithField(logfields.CIDR, cidrNet.String()).Error("skipping too-small pod CIDR")
			p.released[cidrNet.String()] = struct{}{}
			continue
		}
		log.WithField(logfields.CIDR, cidrStr).Debug("created new pod CIDR allocator")
		newIPAllocators = append(newIPAllocators, ipAllocator)
		existingAllocators[cidrStr] = struct{}{} // Protect against duplicate CIDRs.
	}

	if len(p.ipAllocators) > 0 && len(newIPAllocators) == 0 {
		log.Warning("Removed last pod CIDR allocator")
	}

	p.ipAllocators = newIPAllocators
}

func podCIDRFamily(podCIDR string) Family {
	if strings.Contains(podCIDR, ":") {
		return IPv6
	}
	return IPv4
}

// containsCIDR checks if the outer IPNet contains the inner IPNet
func containsCIDR(outer, inner *net.IPNet) bool {
	outerMask, _ := outer.Mask.Size()
	innerMask, _ := inner.Mask.Size()
	return outerMask <= innerMask && outer.Contains(inner.IP)
}

// cleanupUnreachableRoutes remove all unreachable routes for the given pod CIDR.
// This is only needed if EnableUnreachableRoutes has been set.
func cleanupUnreachableRoutes(podCIDR string) error {
	_, removedCIDR, err := net.ParseCIDR(podCIDR)
	if err != nil {
		return err
	}

	var family int
	switch podCIDRFamily(podCIDR) {
	case IPv4:
		family = netlink.FAMILY_V4
	case IPv6:
		family = netlink.FAMILY_V6
	default:
		return errors.New("unknown pod cidr family")
	}

	routes, err := netlink.RouteListFiltered(family, &netlink.Route{
		Table: unix.RT_TABLE_MAIN,
		Type:  unix.RTN_UNREACHABLE,
	}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_TYPE)
	if err != nil {
		return fmt.Errorf("failed to fetch unreachable routes: %w", err)
	}

	var errs error
	for _, route := range routes {
		if !containsCIDR(removedCIDR, route.Dst) {
			continue
		}

		err = netlink.RouteDel(&route)
		if err != nil && !errors.Is(err, unix.ESRCH) {
			// We ignore ESRCH, as it means the entry was already deleted
			errs = errors.Join(errs, fmt.Errorf("failed to delete unreachable route for %s: %w",
				route.Dst.String(), err),
			)
		}
	}
	return errs
}
