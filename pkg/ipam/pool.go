// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"net/netip"
	"slices"

	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var errAllCIDRsExhausted = errors.New("all CIDR ranges are exhausted")

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
//
// Whether a removed CIDR that shows up in the input again may be used again
// depends on who owns the input. If the input is written by the operator only
// (e.g. derived from Status.ENI in ENI mode), its reappearance means the
// operator re-assigned the CIDR to this node, so updatePool is called with
// regainRemoved set and the CIDR becomes allocatable again. If the input is
// also the agent's own output (generic multi-pool mode, where the agent
// re-publishes removed CIDRs as described above), the reappearance may just be
// that echo, and the CIDR stays removed until it is no longer in use.
// Independently of the input owner, the removed mark of a CIDR is dropped once
// the CIDR is neither in the input nor backed by an allocator: at that point
// the agent no longer publishes it, so a later reappearance can only come from
// the operator. Until then, a removed CIDR whose allocator has been released
// is not reclaimed in generic multi-pool mode, even while it is in the input:
// that input may still be the agent's own earlier echo, written before the
// release, while the operator has given the CIDR to another node. This lasts
// until the operator has processed the agent's next publication, which no
// longer lists the CIDR.
//
// Allocators never overlap, so every IP is tracked by at most one allocator
// and the used and free counts of the allocators add up exactly. A CIDR
// whose allocatable addresses are all covered by an existing allocator does
// not get an allocator of its own. A CIDR that covers existing allocators
// absorbs them: it takes over their used IPs, and they, together with their
// removed marks, are dropped. This happens e.g. when an IP that was in use as
// a /32 secondary address is later assigned as part of a delegated /28.
//
// An input CIDR covered by a removed allocator is still published as in use,
// although it has no allocator of its own: its IPs may be in use through the
// removed allocator, and the operator must not release it. This happens e.g.
// when an IP of a detached but in-use /28 is re-assigned as a /32. Once the
// removed allocator goes away, the covered CIDR is released and marked
// removed, like the CIDR of that allocator.
type cidrPool struct {
	logger       *slog.Logger
	mutex        lock.Mutex
	ipAllocators []*ipallocator.Range
	released     map[netip.Prefix]struct{}
	removed      map[netip.Prefix]struct{}
	// covered holds the CIDRs in the input that did not get an allocator
	// because an existing allocator covers them. It only serves to log
	// each of them once rather than on every update.
	covered map[netip.Prefix]struct{}
	// coveredByRemoved maps the CIDRs in the input that are covered by a
	// removed allocator to the CIDR of that allocator. They are published
	// by inUseCIDRs, but never get an allocator and do not count towards
	// the used and free IPs.
	coveredByRemoved map[netip.Prefix]netip.Prefix
	// allowFirstIP and allowLastIP make the pool include the first and last IPs
	// of each CIDR (normally reserved as network/broadcast). This is used for
	// delegated prefixes where the range is exclusively assigned.
	allowFirstIP bool
	allowLastIP  bool
}

// newCIDRPool creates a new CIDR pool.
func newCIDRPool(logger *slog.Logger, allowFirstIP, allowLastIP bool) *cidrPool {
	return &cidrPool{
		logger:       logger,
		released:     map[netip.Prefix]struct{}{},
		removed:      map[netip.Prefix]struct{}{},
		covered:      map[netip.Prefix]struct{}{},
		allowFirstIP: allowFirstIP,
		allowLastIP:  allowLastIP,

		coveredByRemoved: map[netip.Prefix]netip.Prefix{},
	}
}

// cidrRangeOpts returns the ipallocator range options matching the pool's
// first/last IP settings. Delegated prefixes set both, so the network and
// broadcast addresses of each CIDR become allocatable.
func (p *cidrPool) cidrRangeOpts() []ipallocator.CIDRRangeOption {
	var opts []ipallocator.CIDRRangeOption
	if p.allowFirstIP {
		opts = append(opts, ipallocator.WithAllowFirstIP())
	}
	if p.allowLastIP {
		opts = append(opts, ipallocator.WithAllowLastIP())
	}
	return opts
}

// allocatorForLocked returns the allocator that can hand out addr, or nil.
// Allocators do not overlap, so there is at most one.
func (p *cidrPool) allocatorForLocked(addr netip.Addr) *ipallocator.Range {
	for _, ipAllocator := range p.ipAllocators {
		if ipAllocator.Contains(addr) {
			return ipAllocator
		}
	}
	return nil
}

func (p *cidrPool) allocate(addr netip.Addr) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if ipAllocator := p.allocatorForLocked(addr); ipAllocator != nil {
		return ipAllocator.Allocate(addr)
	}
	// addr is not allocatable. Report why if a CIDR contains it, e.g. the
	// network address of a CIDR.
	for _, ipAllocator := range p.ipAllocators {
		if ipAllocator.CIDR().Contains(addr) {
			return ipAllocator.Allocate(addr)
		}
	}

	return fmt.Errorf("IP %s not in range of any CIDR", addr)
}

// allocatorSet is an ordered list of allocators that do not overlap. It is
// indexed by CIDR, so that finding the allocators that overlap a new CIDR
// does not need to look at all of them.
type allocatorSet struct {
	list     []*ipallocator.Range
	byPrefix map[netip.Prefix]*ipallocator.Range
	// minBits and maxBits bound the prefix lengths in byPrefix. Removals
	// do not update them, so they may be loose.
	minBits, maxBits int
}

// newAllocatorSet returns an allocatorSet that takes ownership of list.
func newAllocatorSet(list []*ipallocator.Range) *allocatorSet {
	s := &allocatorSet{
		list:     list,
		byPrefix: make(map[netip.Prefix]*ipallocator.Range, len(list)),
		minBits:  math.MaxInt,
	}
	for _, r := range list {
		s.add(r)
	}
	return s
}

func (s *allocatorSet) add(r *ipallocator.Range) {
	s.byPrefix[r.CIDR()] = r
	s.minBits = min(s.minBits, r.CIDR().Bits())
	s.maxBits = max(s.maxBits, r.CIDR().Bits())
}

// overlapping returns the allocators whose CIDR contains prefix or is
// contained in prefix. Only these can share an allocatable address with an
// allocator for prefix, since two CIDRs are either nested or disjoint.
func (s *allocatorSet) overlapping(prefix netip.Prefix) []*ipallocator.Range {
	var out []*ipallocator.Range
	for bits := prefix.Bits(); bits >= s.minBits; bits-- {
		outer, _ := prefix.Addr().Prefix(bits)
		if r, ok := s.byPrefix[outer]; ok {
			out = append(out, r)
		}
	}
	if s.maxBits > prefix.Bits() {
		for _, r := range s.list {
			if inner := r.CIDR(); inner.Bits() > prefix.Bits() && prefix.Contains(inner.Addr()) {
				out = append(out, r)
			}
		}
	}
	return out
}

// replace appends r and drops the allocators in absorbed.
func (s *allocatorSet) replace(absorbed []*ipallocator.Range, r *ipallocator.Range) {
	for _, a := range absorbed {
		delete(s.byPrefix, a.CIDR())
	}
	if len(absorbed) > 0 {
		s.list = slices.DeleteFunc(s.list, func(a *ipallocator.Range) bool {
			return slices.Contains(absorbed, a)
		})
	}
	s.list = append(s.list, r)
	s.add(r)
}

// newAllocator returns an allocator for prefix that does not overlap any of
// the allocators in existing, and the allocators in existing that it covers.
// The new allocator has taken over the used IPs of the latter, so the caller
// must replace them with it. newAllocator returns nil if prefix must not get
// an allocator: if an allocator in existing covers it, or if it overlaps an
// allocator in existing without covering it.
func (p *cidrPool) newAllocator(prefix netip.Prefix, existing *allocatorSet) (*ipallocator.Range, []*ipallocator.Range) {
	ipAllocator := ipallocator.NewCIDRRange(prefix, p.cidrRangeOpts()...)

	var absorbed []*ipallocator.Range
	for _, other := range existing.overlapping(prefix) {
		switch {
		case !other.Overlaps(ipAllocator):
			// Without allowFirstIP (generic multi-pool mode), e.g. a /32 at
			// the network address of a /24 does not overlap the allocatable
			// addresses of the /24, so both get an allocator.
			continue
		case other.Covers(ipAllocator):
			p.warnCoveredOnce(prefix, other.CIDR(), "skipping CIDR covered by an existing CIDR")
			return nil, nil
		case ipAllocator.Covers(other):
			absorbed = append(absorbed, other)
		default:
			// Only possible for a /31 or /127 at the edge of a CIDR whose
			// first or last address is not allocatable.
			p.warnCoveredOnce(prefix, other.CIDR(), "skipping CIDR overlapping an existing CIDR")
			return nil, nil
		}
	}

	for _, other := range absorbed {
		other.ForEach(func(addr netip.Addr) {
			// Cannot fail: ipAllocator covers other and is still fresh.
			_ = ipAllocator.Allocate(addr)
		})
	}
	return ipAllocator, absorbed
}

// addAllocatorLocked adds ipAllocator, as returned by newAllocator, to
// allocators in place of the allocators it absorbed. The absorbed CIDRs lose
// their marks: their IPs are now managed by ipAllocator.
func (p *cidrPool) addAllocatorLocked(allocators *allocatorSet, ipAllocator *ipallocator.Range, absorbed []*ipallocator.Range) {
	for _, other := range absorbed {
		p.logger.Info(
			"absorbing CIDR into containing CIDR",
			logfields.CIDR, other.CIDR(),
			logfields.ContainingCIDR, ipAllocator.CIDR(),
		)
		delete(p.removed, other.CIDR())
		delete(p.released, other.CIDR())
		for prefix, covering := range p.coveredByRemoved {
			if covering == other.CIDR() {
				delete(p.coveredByRemoved, prefix)
			}
		}
	}
	delete(p.covered, ipAllocator.CIDR())
	delete(p.coveredByRemoved, ipAllocator.CIDR())
	allocators.replace(absorbed, ipAllocator)
}

// warnCoveredOnce logs that prefix gets no allocator because of the
// allocator of other, unless that was logged before.
func (p *cidrPool) warnCoveredOnce(prefix, other netip.Prefix, msg string) {
	if _, logged := p.covered[prefix]; logged {
		return
	}
	p.logger.Warn(msg,
		logfields.CIDR, prefix,
		logfields.ContainingCIDR, other,
	)
	p.covered[prefix] = struct{}{}
}

// releaseCoveredLocked releases the CIDRs covered by the removed CIDR cidr,
// whose allocator is going away, and marks them removed: like cidr, they may
// still be in the input only as the agent's own echo, see cidrPool.
func (p *cidrPool) releaseCoveredLocked(cidr netip.Prefix) {
	for prefix, covering := range p.coveredByRemoved {
		if covering != cidr {
			continue
		}
		p.logger.Debug(
			"releasing CIDR covered by a released CIDR",
			logfields.CIDR, prefix,
			logfields.ContainingCIDR, cidr,
		)
		p.released[prefix] = struct{}{}
		p.removed[prefix] = struct{}{}
		delete(p.coveredByRemoved, prefix)
	}
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

	return netip.Addr{}, errAllCIDRsExhausted
}

func (p *cidrPool) release(addr netip.Addr) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if ipAllocator := p.allocatorForLocked(addr); ipAllocator != nil {
		ipAllocator.Release(addr)
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

func (p *cidrPool) inUseCIDRs() []iputil.Prefix {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.inUseCIDRsLocked()
}

func (p *cidrPool) inUseCIDRsLocked() []iputil.Prefix {
	CIDRs := make([]iputil.Prefix, 0, len(p.ipAllocators)+len(p.coveredByRemoved))
	for _, ipAllocator := range p.ipAllocators {
		CIDRs = append(CIDRs, iputil.PrefixFrom(ipAllocator.CIDR()))
	}
	for _, prefix := range slices.SortedFunc(maps.Keys(p.coveredByRemoved), netip.Prefix.Compare) {
		CIDRs = append(CIDRs, iputil.PrefixFrom(prefix))
	}
	return CIDRs
}

func (p *cidrPool) dump() (allocated sets.Set[netip.Addr], usedIPs, freeIPs, numCIDRs int, err error) {
	// TODO(gandro): Use the Snapshot interface to avoid locking during dump
	p.mutex.Lock()
	defer p.mutex.Unlock()

	allocated = sets.New[netip.Addr]()
	for _, ipAllocator := range p.ipAllocators {
		usedIPs += ipAllocator.Used()
		if _, removed := p.removed[ipAllocator.CIDR()]; !removed {
			freeIPs += ipAllocator.Free()
		}
		ipAllocator.ForEach(func(addr netip.Addr) {
			allocated.Insert(addr)
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

	// Removed CIDRs are not allocatable, so their free IPs do not count
	// towards the free-IP buffer.
	totalFree := 0
	for _, ipAllocator := range p.ipAllocators {
		if _, removed := p.removed[ipAllocator.CIDR()]; removed {
			continue
		}
		totalFree += ipAllocator.Free()
	}

	// Reclaim previously-released CIDRs when demand has grown back and we
	// no longer have enough free IPs. A CIDR stays in p.released only while
	// it is still advertised in the CiliumNode (updatePool removes it from
	// the set as soon as the operator stops advertising it), so reclaiming
	// here never re-adds a CIDR that has actually been detached. Without
	// this, a released-but-still-attached prefix is stranded forever: the
	// operator may not detach it (e.g. release-excess-ips disabled), so it
	// never leaves the advertised set, while updatePool refuses to recreate
	// its allocator because it is still in p.released. The result is
	// permanent exhaustion until the agent restarts.
	if totalFree < neededIPs && len(p.released) > 0 {
		// Reclaim in a deterministic order to avoid churn across calls.
		reclaim := slices.SortedFunc(maps.Keys(p.released), func(a, b netip.Prefix) int {
			if c := a.Addr().Compare(b.Addr()); c != 0 {
				return c
			}
			return a.Bits() - b.Bits()
		})

		allocators := newAllocatorSet(p.ipAllocators)
		for _, prefix := range reclaim {
			if totalFree >= neededIPs {
				break
			}
			if _, removed := p.removed[prefix]; removed {
				continue // not allocatable, see updatePool
			}
			if ipallocator.RangeSize(prefix) == 0 {
				continue // too-small CIDR, keep it released
			}
			ipAllocator, absorbed := p.newAllocator(prefix, allocators)
			if ipAllocator == nil {
				continue // covered by an allocator, keep it released
			}
			for _, other := range absorbed {
				if _, removed := p.removed[other.CIDR()]; !removed {
					totalFree -= other.Free()
				}
			}
			p.addAllocatorLocked(allocators, ipAllocator, absorbed)
			delete(p.released, prefix)
			totalFree += ipAllocator.Free()
			p.logger.Debug("reclaiming released CIDR", logfields.CIDR, prefix)
		}
		p.ipAllocators = allocators.list
	}

	// Iterate over CIDRs in reverse order, so we prioritize releasing
	// later CIDRs.
	retainedAllocators := []*ipallocator.Range{}
	for _, ipAllocator := range slices.Backward(p.ipAllocators) {
		cidr := ipAllocator.CIDR()

		// If the CIDR is not used and releasing it would
		// not take us below the release threshold, then release it immediately.
		// Unused removed CIDRs are always released: they are not allocatable,
		// and keeping their allocator would keep them published forever.
		free := ipAllocator.Free()
		_, removed := p.removed[cidr]
		if ipAllocator.Used() == 0 && (removed || totalFree-free >= neededIPs) {
			p.released[cidr] = struct{}{}
			if removed {
				p.releaseCoveredLocked(cidr)
			} else {
				totalFree -= free
			}
			p.logger.Debug("releasing CIDR", logfields.CIDR, cidr)
		} else {
			retainedAllocators = append(retainedAllocators, ipAllocator)
		}
	}

	// Reverse the slice before copying to preserve original order. Otherwise
	// the order flips on every call, spreading allocations across different
	// CIDRs and preventing them from being released, leaving the node holding
	// more IPs than needed.
	slices.Reverse(retainedAllocators)
	p.ipAllocators = retainedAllocators
}

// updatePool updates the pool to the given prefixes. regainRemoved must only
// be set if prefixes are authoritative, i.e. owned by the operator and not
// the agent's own published CIDRs, see cidrPool.
func (p *cidrPool) updatePool(prefixes []netip.Prefix, regainRemoved bool) {
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

	// Forget covered CIDRs no longer present in the CRD, so that
	// releaseCoveredLocked does not release them.
	for prefix := range p.coveredByRemoved {
		if _, ok := prefixSet[prefix]; !ok {
			delete(p.coveredByRemoved, prefix)
		}
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

	// Add existing IP allocators to newIPAllocators in order.
	for _, ipAllocator := range p.ipAllocators {
		cidr := ipAllocator.CIDR()
		if _, ok := prefixSet[cidr]; !ok {
			if ipAllocator.Used() == 0 {
				if _, removed := p.removed[cidr]; removed {
					p.releaseCoveredLocked(cidr)
				}
				continue
			}
			p.logger.Error(
				"in-use CIDR was removed from spec",
				logfields.CIDR, cidr,
			)
			p.removed[cidr] = struct{}{}
		}
		newIPAllocators = append(newIPAllocators, ipAllocator)
	}

	// Create and add new IP allocators. allocators.byPrefix is the set of
	// CIDRs that have a corresponding allocator.
	allocators := newAllocatorSet(newIPAllocators)
	for _, prefix := range prefixes {
		if _, ok := allocators.byPrefix[prefix]; ok {
			continue
		}
		if _, ok := p.released[prefix]; ok {
			continue
		}
		if ipallocator.RangeSize(prefix) == 0 {
			p.logger.Error(
				"skipping too-small CIDR",
				logfields.CIDR, prefix,
			)
			p.released[prefix] = struct{}{}
			continue
		}
		ipAllocator, absorbed := p.newAllocator(prefix, allocators)
		if ipAllocator == nil {
			continue
		}
		p.logger.Debug(
			"created new CIDR allocator",
			logfields.CIDR, prefix,
		)
		p.addAllocatorLocked(allocators, ipAllocator, absorbed)
	}
	newIPAllocators = allocators.list

	for cidr := range p.removed {
		_, inInput := prefixSet[cidr]
		_, hasAllocator := allocators.byPrefix[cidr]
		switch {
		case inInput && regainRemoved:
			// The operator re-advertised the CIDR, it is allocatable again.
			p.logger.Info(
				"regained previously removed CIDR",
				logfields.CIDR, cidr,
			)
			delete(p.removed, cidr)
		case !inInput && !hasAllocator:
			// The CIDR is no longer published by the agent, so any later
			// reappearance in the input comes from the operator.
			delete(p.removed, cidr)
		}
	}

	// Forget covered CIDRs that are no longer in the input, so that they
	// are logged again if they come back.
	for prefix := range p.covered {
		if _, ok := prefixSet[prefix]; !ok {
			delete(p.covered, prefix)
		}
	}

	// Keep publishing the input CIDRs covered by a removed allocator.
	clear(p.coveredByRemoved)
	for prefix := range prefixSet {
		if _, ok := allocators.byPrefix[prefix]; ok || len(p.removed) == 0 {
			continue
		}
		for bits := prefix.Bits() - 1; bits >= allocators.minBits; bits-- {
			outer, _ := prefix.Addr().Prefix(bits)
			if _, ok := allocators.byPrefix[outer]; !ok {
				continue
			}
			if _, removed := p.removed[outer]; removed {
				p.coveredByRemoved[prefix] = outer
			}
			break
		}
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
