// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
	"github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// A cidrPool manages the allocation of IPs in multiple CIDRs.
// It maintains one IP allocator for each CIDR in the pool.
// Unused CIDRs which have been marked as released, but not yet deleted
// from the local CiliumNode CRD by the operator are put into the released set.
// Once the operator removes a released CIDR from the CiliumNode CRD spec,
// it is also deleted from the release set.
// CIDRs which have been erroneously deleted from the CiliumNode CRD spec
// (either by a buggy operator or by manual/human changes CRD) are marked in
// the removed map. If IP addresses have been allocated from such a CIDR,
// its allocator is kept around. But no new IPs will be allocated from this
// CIDR. By keeping removed CIDRs in the CiliumNode CRD status, we indicate
// to the operator that we would like to re-gain ownership over that CIDR.
type cidrPool struct {
	logger       *slog.Logger
	mutex        lock.Mutex
	ipAllocators []*ipallocator.Range
	released     map[netip.Prefix]struct{}
	removed      map[netip.Prefix]struct{}
	// allowFirstLastIPs, when true, makes the pool include the first and last
	// IPs of each CIDR (normally reserved as network/broadcast). This is used
	// for delegated prefixes where the entire range is exclusively assigned.
	allowFirstLastIPs bool
}

// newCIDRPool creates a new CIDR pool.
func newCIDRPool(logger *slog.Logger, allowFirstLastIPs bool) *cidrPool {
	return &cidrPool{
		logger:            logger,
		released:          map[netip.Prefix]struct{}{},
		removed:           map[netip.Prefix]struct{}{},
		allowFirstLastIPs: allowFirstLastIPs,
	}
}

func (p *cidrPool) allocate(addr netip.Addr) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, ipAllocator := range p.ipAllocators {
		if ipAllocator.CIDR().Contains(addr) {
			return ipAllocator.Allocate(addr)
		}
	}

	return fmt.Errorf("IP %s not in range of any CIDR", addr)
}

func (p *cidrPool) allocateNext() (netip.Addr, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// When allocating a random IP, we try the CIDRs in the order they are
	// listed in the CRD. This avoids internal fragmentation.
	for _, ipAllocator := range p.ipAllocators {
		if _, removed := p.removed[ipAllocator.CIDR()]; removed {
			continue
		}
		if ipAllocator.Free() == 0 {
			continue
		}
		return ipAllocator.AllocateNext()
	}

	return netip.Addr{}, errors.New("all CIDR ranges are exhausted")
}

func (p *cidrPool) release(addr netip.Addr) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, ipAllocator := range p.ipAllocators {
		if ipAllocator.CIDR().Contains(addr) {
			ipAllocator.Release(addr)
			return
		}
	}
}

func (p *cidrPool) hasAvailableIPs() bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, ipAllocator := range p.ipAllocators {
		if _, removed := p.removed[ipAllocator.CIDR()]; removed {
			continue
		}
		if ipAllocator.Free() > 0 {
			return true
		}
	}

	return false
}

func (p *cidrPool) inUseIPCount() (count int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, ipAllocator := range p.ipAllocators {
		count += ipAllocator.Used()
	}
	return count
}

func (p *cidrPool) inUseCIDRs() []types.IPAMCIDR {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.inUseCIDRsLocked()
}

func (p *cidrPool) inUseCIDRsLocked() []types.IPAMCIDR {
	CIDRs := make([]types.IPAMCIDR, 0, len(p.ipAllocators))
	for _, ipAllocator := range p.ipAllocators {
		CIDRs = append(CIDRs, types.IPAMCIDR(ipAllocator.CIDR().String()))
	}
	return CIDRs
}

func (p *cidrPool) dump() (ipToOwner map[string]string, usedIPs, freeIPs, numCIDRs int, err error) {
	// TODO(gandro): Use the Snapshot interface to avoid locking during dump
	p.mutex.Lock()
	defer p.mutex.Unlock()

	ipToOwner = map[string]string{}
	for _, ipAllocator := range p.ipAllocators {
		usedIPs += ipAllocator.Used()
		if _, removed := p.removed[ipAllocator.CIDR()]; !removed {
			freeIPs += ipAllocator.Free()
		}
		ipAllocator.ForEach(func(addr netip.Addr) {
			ipToOwner[addr.String()] = ""
		})
	}
	numCIDRs = len(p.ipAllocators)

	return
}

func (p *cidrPool) capacity() (freeIPs int) {
	// TODO(gandro): Use the Snapshot interface to avoid locking during dump
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, ipAllocator := range p.ipAllocators {
		if _, removed := p.removed[ipAllocator.CIDR()]; !removed {
			freeIPs += ipAllocator.Free()
		}
	}

	return
}

// releaseExcessCIDRsMultiPool implements the logic for multi-pool IPAM
func (p *cidrPool) releaseExcessCIDRsMultiPool(neededIPs int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	totalFree := 0
	for _, ipAllocator := range p.ipAllocators {
		totalFree += ipAllocator.Free()
	}

	// Iterate over CIDRs in reverse order, so we prioritize releasing
	// later CIDRs.
	retainedAllocators := []*ipallocator.Range{}
	for i := len(p.ipAllocators) - 1; i >= 0; i-- {
		ipAllocator := p.ipAllocators[i]
		cidr := ipAllocator.CIDR()

		// If the CIDR is not used and releasing it would
		// not take us below the release threshold, then release it immediately
		free := ipAllocator.Free()
		if ipAllocator.Used() == 0 && totalFree-free >= neededIPs {
			p.released[cidr] = struct{}{}
			totalFree -= free
			p.logger.Debug("releasing CIDR", logfields.CIDR, cidr)
		} else {
			retainedAllocators = append(retainedAllocators, ipAllocator)
		}
	}

	p.ipAllocators = retainedAllocators
}

func (p *cidrPool) updatePool(prefixes []netip.Prefix) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if option.Config.Debug {
		p.logger.Debug(
			"Updating IPAM pool",
			logfields.NewCIDR, prefixes,
			logfields.OldCIDR, p.inUseCIDRsLocked(),
		)
	}

	// De-duplicate prefixes.
	prefixSet := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		if _, ok := prefixSet[prefix]; ok {
			p.logger.Error(
				"ignoring duplicate CIDR",
				logfields.CIDR, prefix,
			)
			continue
		}
		prefixSet[prefix] = struct{}{}
	}

	// Forget any released CIDRs no longer present in the CRD.
	for prefix := range p.released {
		if _, ok := prefixSet[prefix]; !ok {
			p.logger.Debug(
				"removing released CIDR",
				logfields.CIDR, prefix,
			)
			delete(p.released, prefix)
		}

		if option.Config.EnableUnreachableRoutes {
			if err := cleanupUnreachableRoutes(prefix); err != nil {
				p.logger.Warn(
					"failed to remove unreachable routes for cidr",
					logfields.Error, err,
					logfields.CIDR, prefix,
				)
			}
		}
	}

	// newIPAllocators is the new slice of IP allocators.
	newIPAllocators := make([]*ipallocator.Range, 0, len(prefixes))

	// existingAllocators is the set of CIDRs that have a corresponding allocator
	existingAllocators := make(map[netip.Prefix]struct{}, len(p.ipAllocators))

	// Add existing IP allocators to newIPAllocators in order.
	for _, ipAllocator := range p.ipAllocators {
		cidr := ipAllocator.CIDR()
		if _, ok := prefixSet[cidr]; !ok {
			if ipAllocator.Used() == 0 {
				continue
			}
			p.logger.Error(
				"in-use CIDR was removed from spec",
				logfields.CIDR, cidr,
			)
			p.removed[cidr] = struct{}{}
		}
		newIPAllocators = append(newIPAllocators, ipAllocator)
		existingAllocators[cidr] = struct{}{}
	}

	// Create and add new IP allocators to newIPAllocators.
	var rangeOpts []ipallocator.CIDRRangeOption
	if p.allowFirstLastIPs {
		rangeOpts = append(rangeOpts, ipallocator.WithAllowFirstLastIPs())
	}
	for _, prefix := range prefixes {
		if _, ok := existingAllocators[prefix]; ok {
			continue
		}
		if _, ok := p.released[prefix]; ok {
			continue
		}
		ipAllocator := ipallocator.NewCIDRRange(prefix, rangeOpts...)
		if ipAllocator.Free() == 0 {
			p.logger.Error(
				"skipping too-small CIDR",
				logfields.CIDR, prefix,
			)
			p.released[prefix] = struct{}{}
			continue
		}
		p.logger.Debug(
			"created new CIDR allocator",
			logfields.CIDR, prefix,
		)
		newIPAllocators = append(newIPAllocators, ipAllocator)
		existingAllocators[prefix] = struct{}{} // Protect against duplicate CIDRs.
	}

	if len(p.ipAllocators) > 0 && len(newIPAllocators) == 0 {
		p.logger.Warn("Removed last CIDR allocator")
	}

	p.ipAllocators = newIPAllocators
}

func prefixFamily(prefix netip.Prefix) Family {
	if prefix.Addr().Is6() {
		return IPv6
	}
	return IPv4
}

// containsPrefix checks if the outer prefix fully contains the inner prefix.
func containsPrefix(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// cleanupUnreachableRoutes removes all unreachable routes for the given prefix.
// This is only needed if EnableUnreachableRoutes has been set.
func cleanupUnreachableRoutes(prefix netip.Prefix) error {
	var family int
	switch prefixFamily(prefix) {
	case IPv4:
		family = netlink.FAMILY_V4
	case IPv6:
		family = netlink.FAMILY_V6
	default:
		return errors.New("unknown cidr family")
	}

	routes, err := safenetlink.RouteListFiltered(family, &netlink.Route{
		Table: unix.RT_TABLE_MAIN,
		Type:  unix.RTN_UNREACHABLE,
	}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_TYPE)
	if err != nil {
		return fmt.Errorf("failed to fetch unreachable routes: %w", err)
	}

	var errs error
	for _, route := range routes {
		if route.Dst == nil {
			continue
		}
		routePrefix, ok := netipx.FromStdIPNet(route.Dst)
		if !ok {
			continue
		}
		if !containsPrefix(prefix, routePrefix) {
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
