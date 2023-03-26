// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package podcidr

import (
	"fmt"
	"net"
	"sort"

	"github.com/cilium/cilium/pkg/ipam/allocator/clusterpool/cidralloc"

	"github.com/sirupsen/logrus"
	"go.uber.org/multierr"

	"github.com/cilium/cilium/pkg/cidr"
	ipPkg "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

type specPodCIDRs []*net.IPNet

func (s specPodCIDRs) Contains(other *net.IPNet) bool {
	for _, ipNet := range s {
		if cidr.Equal(ipNet, other) {
			return true
		}
	}
	return false
}

type podCIDRStatus struct {
	ipNet  *net.IPNet
	status types.PodCIDRStatus
}

type statusPodCIDRs []podCIDRStatus

func (s statusPodCIDRs) Contains(other *net.IPNet) bool {
	for _, c := range s {
		if cidr.Equal(c.ipNet, other) {
			return true
		}
	}
	return false
}

func (s statusPodCIDRs) Sort() {
	sort.SliceStable(s, func(i, j int) bool {
		return s[i].ipNet.String() < s[j].ipNet.String()
	})
}

type nodeAction struct {
	// allocateNext is set to true to indicate that a new pod CIDR should be
	// allocated and added to this node's podCIDR list
	allocateNext bool
	// release contains a list of CIDRs which can be deallocated and removed
	// from this node's podCIDR list
	release []*net.IPNet
	// reuse contains a list of CIDRs which we want mark as occupied and keep
	// in this node's podCIDR list. This list is guaranteed to have the same
	// pod CIDRs order as node.Spec.IPAM.PodCIDRs.
	reuse []*net.IPNet
	// needsResync is set to true if the internal allocator state is not
	// reflected in the CiliumNode CRD and therefore needs to be resynced.
	needsResync bool
}

func (a *nodeAction) performNodeAction(
	allocators []cidralloc.CIDRAllocator,
	allocType allocatorType,
	allocatedCIDRs []*net.IPNet,
) (result []*net.IPNet, changed bool, errs error) {
	result = append([]*net.IPNet(nil), allocatedCIDRs...)

	if len(a.reuse) > 0 {
		_, err := allocateIPNet(allocType, allocators, a.reuse)
		if err != nil {
			errs = multierr.Append(errs, err)
		} else {
			result = append(result, a.reuse...)
			changed = true
		}
	}

	if len(a.release) > 0 {
		releaseCIDRs(allocators, a.release)
		result = cidr.RemoveAll(result, a.release)
		changed = true
	}

	if a.allocateNext {
		_, cidr, err := allocateFirstFreeCIDR(allocators)
		if err != nil {
			errs = multierr.Append(errs, err)
		} else {
			result = append(result, cidr)
			changed = true
		}
	}

	return result, changed, errs
}

func buildNodeAction(
	spec specPodCIDRs,
	status statusPodCIDRs,
	allocatedCIDRs []*net.IPNet,
	hasAllocators bool,
) (action nodeAction) {
	// Keeps track of any CIDRs we do not want to reuse, i.e. any CIDRs which
	// are either already allocated, marked for released, or already released
	noReuseCIDRs := map[string]struct{}{}
	for _, podCIDR := range allocatedCIDRs {
		noReuseCIDRs[podCIDR.String()] = struct{}{}
	}

	// Check if node has any in in-use or released pod CIDRs
	hasAvailablePodCIDR := false
	for _, statusCIDR := range status {
		podCIDR := statusCIDR.ipNet
		switch statusCIDR.status {
		case types.PodCIDRStatusReleased:
			// Never reuse CIDRs marked for release
			noReuseCIDRs[podCIDR.String()] = struct{}{}
			// Only actually release the CIDRs which have been allocated to this node
			if cidr.Contains(allocatedCIDRs, podCIDR) {
				action.release = append(action.release, podCIDR)
			}
		case types.PodCIDRStatusDepleted:
			// If the node only contains depleted and released CIDRs, the next
			// case ("in-use") will never be hit and we will allocate a new
			// CIDR for this node.
		case types.PodCIDRStatusInUse:
			hasAvailablePodCIDR = true
		}
	}

	// If we find an unused CIDR, i.e. one that is present in .Spec, but absent
	// in .Status, we do not have to allocate a new CIDR for this node.
	for _, specCIDR := range spec {
		if status.Contains(specCIDR) {
			continue
		}
		hasAvailablePodCIDR = true
	}

	// Only allocate if a node has no available pod CIDRs in either .Spec or .Status
	action.allocateNext = hasAllocators && !hasAvailablePodCIDR

	// If there are any existing pod CIDRs in either .Spec or .Status which
	// have neither been allocated to the node yet nor are marked for release,
	// we want to reuse them, meaning marking them as allocated such that
	// they are not accidentally handed out to any other node. We add each
	// reused pod CIDR to noReuseCIDRs to avoid duplicates.
	//
	// Note: We iterate over spec and then status to preserve the order
	// in which the CIDRs are listed in the CiliumNode CRD.
	for _, podCIDR := range spec {
		podCIDRStr := podCIDR.String()
		if _, ok := noReuseCIDRs[podCIDRStr]; !ok {
			action.reuse = append(action.reuse, podCIDR)
			noReuseCIDRs[podCIDRStr] = struct{}{}
		}
	}
	for _, podCIDR := range status {
		podCIDRStr := podCIDR.ipNet.String()
		if _, ok := noReuseCIDRs[podCIDRStr]; !ok {
			action.reuse = append(action.reuse, podCIDR.ipNet)
			noReuseCIDRs[podCIDRStr] = struct{}{}
		}
	}

	// If we find any allocated pod CIDRs which are absent in the
	// CiliumNode CRD, we want to resync the CRD to ensure they get added back in.
	for _, podCIDR := range allocatedCIDRs {
		if !spec.Contains(podCIDR) && !cidr.Contains(action.release, podCIDR) {
			action.needsResync = true
			break
		}
	}

	return action
}

// updateNode is set to true if the CiliumNode CRD needs to be updated
// based on the determined node actions
func determineNodeActions(node *v2.CiliumNode, hasV4Allocators, hasV6Allocators bool, v4PodCIDRs, v6PodCIDRs []*net.IPNet) (v4Action, v6Action nodeAction, err error) {
	v4PodCIDRSpec, v6PodCIDRSpec, v4PodCIDRStatus, v6PodCIDRStatus, err := extractPodCIDRs(node)
	if err != nil {
		return v4Action, v6Action, err
	}

	v4Action = buildNodeAction(v4PodCIDRSpec, v4PodCIDRStatus, v4PodCIDRs, hasV4Allocators)
	v6Action = buildNodeAction(v6PodCIDRSpec, v6PodCIDRStatus, v6PodCIDRs, hasV6Allocators)

	return v4Action, v6Action, nil
}

func extractPodCIDRs(node *v2.CiliumNode) (
	v4PodCIDRSpec, v6PodCIDRSpec specPodCIDRs,
	v4PodCIDRStatus, v6PodCIDRStatus statusPodCIDRs,
	err error,
) {
	for _, podCIDRStr := range node.Spec.IPAM.PodCIDRs {
		_, podCIDR, err := net.ParseCIDR(podCIDRStr)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("invalid pod CIDR in .Spec.IPAM.PodCIDRs: %w", err)
		}

		if ipPkg.IsIPv4(podCIDR.IP) {
			v4PodCIDRSpec = append(v4PodCIDRSpec, podCIDR)
		} else {
			v6PodCIDRSpec = append(v6PodCIDRSpec, podCIDR)
		}
	}

	for podCIDRStr, s := range node.Status.IPAM.PodCIDRs {
		_, podCIDR, err := net.ParseCIDR(podCIDRStr)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("invalid pod CIDR in .Status.IPAM.PodCIDRs: %w", err)
		}

		status := podCIDRStatus{
			ipNet:  podCIDR,
			status: s.Status,
		}

		if ipPkg.IsIPv4(podCIDR.IP) {
			v4PodCIDRStatus = append(v4PodCIDRStatus, status)
		} else {
			v6PodCIDRStatus = append(v6PodCIDRStatus, status)
		}
	}

	// The iteration order of Golang maps is random. Sort status CIDRs to ensure
	// deterministic behavior
	v4PodCIDRStatus.Sort()
	v6PodCIDRStatus.Sort()

	return v4PodCIDRSpec, v6PodCIDRSpec, v4PodCIDRStatus, v6PodCIDRStatus, nil
}

func (n *NodesPodCIDRManager) allocateNodeV2(node *v2.CiliumNode) (cn *v2.CiliumNode, updateSpec, updateStatus bool, err error) {
	log = log.WithFields(logrus.Fields{
		"node-name": node.Name,
	})

	// list of pod CIDRs already allocated to this node
	allocated, ok := n.nodes[node.Name]
	if !ok {
		allocated = &nodeCIDRs{}
	}

	// determines the allocation actions to be performed on this node
	hasV4Allocators := len(n.v4CIDRAllocators) != 0
	hasV6Allocators := len(n.v6CIDRAllocators) != 0
	v4Action, v6Action, err := determineNodeActions(node, hasV4Allocators, hasV6Allocators, allocated.v4PodCIDRs, allocated.v6PodCIDRs)
	if err != nil {
		cn = node.DeepCopy()
		cn.Status.IPAM.OperatorStatus.Error = err.Error()
		return cn, false, true, nil
	}

	// cannot allocate until we have received all existing node objects
	postponeAllocation := (v4Action.allocateNext || v6Action.allocateNext) && !n.canAllocatePodCIDRs
	if postponeAllocation {
		v4Action.allocateNext = false
		v6Action.allocateNext = false
	}

	v4PodCIDRs, v4Changed, v4Errors := v4Action.performNodeAction(n.v4CIDRAllocators, v4AllocatorType, allocated.v4PodCIDRs)
	v6PodCIDRs, v6Changed, v6Errors := v6Action.performNodeAction(n.v6CIDRAllocators, v6AllocatorType, allocated.v6PodCIDRs)
	err = multierr.Combine(v4Errors, v6Errors)

	updateStatus = err != nil
	updateSpec = (v4Changed || v4Action.needsResync) || (v6Changed || v6Action.needsResync)

	if !(postponeAllocation || updateSpec || updateStatus) {
		return nil, false, false, nil // no-op

	}

	cn = node.DeepCopy()
	if updateSpec {
		n.nodes[node.Name] = &nodeCIDRs{
			v4PodCIDRs: v4PodCIDRs,
			v6PodCIDRs: v6PodCIDRs,
		}

		cn.Spec.IPAM.PodCIDRs = make([]string, 0, len(v4PodCIDRs)+len(v6PodCIDRs))
		for _, v4CIDR := range v4PodCIDRs {
			cn.Spec.IPAM.PodCIDRs = append(cn.Spec.IPAM.PodCIDRs, v4CIDR.String())
		}
		for _, v6CIDR := range v6PodCIDRs {
			cn.Spec.IPAM.PodCIDRs = append(cn.Spec.IPAM.PodCIDRs, v6CIDR.String())
		}
	}

	// Clear any previous errors
	cn.Status.IPAM.OperatorStatus.Error = ""
	if err != nil {
		cn.Status.IPAM.OperatorStatus.Error = err.Error()
	}

	// queue this node for new CIDR allocation once we've reused all other CIDRs
	if postponeAllocation {
		log.Debug("Postponing new CIDR allocation")
		n.nodesToAllocate[node.Name] = cn
	}

	return cn, updateSpec, updateStatus, nil
}
