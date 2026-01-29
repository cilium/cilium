// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
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
	released     map[string]struct{} // key is a CIDR string, e.g. 10.20.30.0/24
	removed      map[string]struct{} // key is a CIDR string, e.g. 10.20.30.0/24
}

// newCIDRPool creates a new CIDR pool.
func newCIDRPool(logger *slog.Logger) *cidrPool {
	return &cidrPool{
		logger:   logger,
		released: map[string]struct{}{},
		removed:  map[string]struct{}{},
	}
}

func (p *cidrPool) allocate(ip net.IP) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, ipAllocator := range p.ipAllocators {
		cidrNet := ipAllocator.CIDR()
		if cidrNet.Contains(ip) {
			return ipAllocator.Allocate(ip)
		}
	}

	return fmt.Errorf("IP %s not in range of any CIDR", ip)
}

func (p *cidrPool) allocateNext() (net.IP, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// When allocating a random IP, we try the CIDRs in the order they are
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

	return nil, errors.New("all CIDR ranges are exhausted")
}

func (p *cidrPool) release(ip net.IP) {
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

func (p *cidrPool) hasAvailableIPs() bool {
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
		ipnet := ipAllocator.CIDR()
		CIDRs = append(CIDRs, types.IPAMCIDR(ipnet.String()))
	}
	return CIDRs
}

func (p *cidrPool) dump() (ipToOwner map[string]string, usedIPs, freeIPs, numCIDRs int, err error) {
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
	numCIDRs = len(p.ipAllocators)

	return
}

func (p *cidrPool) capacity() (freeIPs int) {
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
		cidrNet := ipAllocator.CIDR()
		cidrStr := cidrNet.String()

		// If the CIDR is not used and releasing it would
		// not take us below the release threshold, then release it immediately
		free := ipAllocator.Free()
		if ipAllocator.Used() == 0 && totalFree-free >= neededIPs {
			p.released[cidrStr] = struct{}{}
			totalFree -= free
			p.logger.Debug("releasing CIDR", logfields.CIDR, cidrStr)
		} else {
			retainedAllocators = append(retainedAllocators, ipAllocator)
		}
	}

	p.ipAllocators = retainedAllocators
}

func (p *cidrPool) updatePool(CIDRs []string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if option.Config.Debug {
		p.logger.Debug(
			"Updating IPAM pool",
			logfields.NewCIDR, CIDRs,
			logfields.OldCIDR, p.inUseCIDRsLocked(),
		)
	}

	// Parse the CIDRs, ignoring invalid CIDRs, and de-duplicating them.
	cidrNets := make([]*net.IPNet, 0, len(CIDRs))
	cidrStrSet := make(map[string]struct{}, len(CIDRs))
	for _, cidr := range CIDRs {
		_, cidr, err := net.ParseCIDR(cidr)
		if err != nil {
			p.logger.Error(
				"ignoring invalid CIDR",
				logfields.Error, err,
				logfields.CIDR, CIDRs,
			)
			continue
		}
		if _, ok := cidrStrSet[cidr.String()]; ok {
			p.logger.Error(
				"ignoring duplicate CIDR",
				logfields.CIDR, CIDRs,
			)
			continue
		}
		cidrNets = append(cidrNets, cidr)
		cidrStrSet[cidr.String()] = struct{}{}
	}

	// Forget any released CIDRs no longer present in the CRD.
	for cidrStr := range p.released {
		if _, ok := cidrStrSet[cidrStr]; !ok {
			p.logger.Debug(
				"removing released CIDR",
				logfields.CIDR, cidrStr,
			)
			delete(p.released, cidrStr)
		}

		if option.Config.EnableUnreachableRoutes {
			if err := cleanupUnreachableRoutes(cidrStr); err != nil {
				p.logger.Warn(
					"failed to remove unreachable routes for cidr",
					logfields.Error, err,
					logfields.CIDR, cidrStr,
				)
			}
		}
	}

	// newIPAllocators is the new slice of IP allocators.
	newIPAllocators := make([]*ipallocator.Range, 0, len(CIDRs))

	// addedCIDRs is the set of CIDRs that have a corresponding allocator
	existingAllocators := make(map[string]struct{}, len(p.ipAllocators))

	// Add existing IP allocators to newIPAllocators in order.
	for _, ipAllocator := range p.ipAllocators {
		cidrNet := ipAllocator.CIDR()
		cidrStr := cidrNet.String()
		if _, ok := cidrStrSet[cidrStr]; !ok {
			if ipAllocator.Used() == 0 {
				continue
			}
			p.logger.Error(
				"in-use CIDR was removed from spec",
				logfields.CIDR, cidrStr,
			)
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
			p.logger.Error(
				"skipping too-small CIDR",
				logfields.CIDR, cidrNet,
			)
			p.released[cidrNet.String()] = struct{}{}
			continue
		}
		p.logger.Debug(
			"created new CIDR allocator",
			logfields.CIDR, cidrStr,
		)
		newIPAllocators = append(newIPAllocators, ipAllocator)
		existingAllocators[cidrStr] = struct{}{} // Protect against duplicate CIDRs.
	}

	if len(p.ipAllocators) > 0 && len(newIPAllocators) == 0 {
		p.logger.Warn("Removed last CIDR allocator")
	}

	p.ipAllocators = newIPAllocators
}

func cidrFamily(cidr string) Family {
	if strings.Contains(cidr, ":") {
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

// cleanupUnreachableRoutes remove all unreachable routes for the given CIDR.
// This is only needed if EnableUnreachableRoutes has been set.
func cleanupUnreachableRoutes(cidr string) error {
	_, removedCIDR, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	var family int
	switch cidrFamily(cidr) {
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
