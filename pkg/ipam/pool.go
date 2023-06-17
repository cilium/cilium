// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/defaults"
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
// previouslyReleasedCIDRs contains a list of pod CIDRs which were allocated
// to this node, but have been marked for released before the agent was
// restarted. We keep track of them to avoid accidental use-after-free after an
// agent restart. This parameter is only used for clusterpool-v2beta and will
// be removed.
func newPodCIDRPool(previouslyReleasedCIDRs []string) *podCIDRPool {
	released := make(map[string]struct{}, len(previouslyReleasedCIDRs))
	for _, releasedCIDR := range previouslyReleasedCIDRs {
		released[releasedCIDR] = struct{}{}
	}

	return &podCIDRPool{
		released: released,
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

func (p *podCIDRPool) calculateIPsLocked() (totalUsed, totalFree int) {
	// Compute the total number of free and used IPs for all non-released pod
	// CIDRs.
	for _, r := range p.ipAllocators {
		cidrNet := r.CIDR()
		cidrStr := cidrNet.String()
		if _, released := p.released[cidrStr]; released {
			continue
		}
		totalUsed += r.Used()
		if _, removed := p.removed[cidrStr]; !removed {
			totalFree += r.Free()
		}
	}

	return totalUsed, totalFree
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

// releaseExcessCIDRsLocked implements the logic for clusterpool-v2-beta
func (p *podCIDRPool) releaseExcessCIDRsLocked(totalFree, releaseThreshold int) {
	// Iterate over pod CIDRs in reverse order, so we prioritize releasing
	// later pod CIDRs.
	for i := len(p.ipAllocators) - 1; i >= 0; i-- {
		ipAllocator := p.ipAllocators[i]
		cidrNet := ipAllocator.CIDR()
		cidrStr := cidrNet.String()
		if _, released := p.released[cidrStr]; released || ipAllocator.Used() > 0 {
			// CIDR is either in use or already released
			continue
		}

		if _, removed := p.removed[cidrStr]; removed {
			// If the pod CIDR has been removed, then release it
			p.released[cidrStr] = struct{}{}
			delete(p.removed, cidrStr)
			log.WithField(logfields.CIDR, cidrStr).Debug("releasing removed pod CIDR")
		} else if free := ipAllocator.Free(); totalFree-free >= releaseThreshold {
			// Otherwise, if the pod CIDR is not used and releasing it would
			// not take us below the release threshold, then release it and
			// mark it as released.
			p.released[cidrStr] = struct{}{}
			totalFree -= free
			log.WithField(logfields.CIDR, cidrStr).Debug("releasing pod CIDR")
		}
	}
}

func (p *podCIDRPool) clusterPoolV2Beta1Status(allocationThreshold, releaseThreshold int) types.PodCIDRMap {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if allocationThreshold <= 0 {
		allocationThreshold = defaults.IPAMPodCIDRAllocationThreshold
	}

	if releaseThreshold <= 0 {
		releaseThreshold = defaults.IPAMPodCIDRReleaseThreshold
	}

	_, totalFree := p.calculateIPsLocked()
	p.releaseExcessCIDRsLocked(totalFree, releaseThreshold)

	defaultStatus := types.PodCIDRStatusInUse
	if totalFree < allocationThreshold {
		// If the total number of free IPs is below the allocation threshold,
		// then mark all pod CIDRs as depleted, unless they have already been
		// released.
		defaultStatus = types.PodCIDRStatusDepleted
	}

	result := types.PodCIDRMap{}

	// If the total number of free IPs is below the allocation threshold,
	// then mark all pod CIDRs as depleted, unless they have already been
	// released.
	for _, ipAllocator := range p.ipAllocators {
		cidrNet := ipAllocator.CIDR()
		cidrStr := cidrNet.String()
		if _, released := p.released[cidrStr]; released {
			continue
		}
		status := defaultStatus
		if ipAllocator.Free() == 0 {
			status = types.PodCIDRStatusDepleted
		}

		result[cidrStr] = types.PodCIDRMapEntry{
			Status: status,
		}
	}

	// Mark all released pod CIDRs as released.
	for cidrStr := range p.released {
		result[cidrStr] = types.PodCIDRMapEntry{
			Status: types.PodCIDRStatusReleased,
		}
	}

	return result
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
		ipAllocator, err := ipallocator.NewCIDRRange(cidrNet)
		if err != nil {
			log.WithError(err).WithField(logfields.CIDR, cidrStr).Error("cannot create *ipallocator.Range")
			continue
		}
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
