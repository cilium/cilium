// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/alibabacloud/eni/limits"
	eniTypes "github.com/cilium/cilium/pkg/alibabacloud/eni/types"
	"github.com/cilium/cilium/pkg/alibabacloud/utils"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/stats"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/math"
)

// The following error constants represent the error conditions for
// CreateInterface without additional context embedded in order to make them
// usable for metrics accounting purposes.
const (
	errUnableToDetermineLimits   = "unable to determine limits"
	unableToDetermineLimits      = "unableToDetermineLimits"
	errUnableToGetSecurityGroups = "unable to get security groups"
	unableToGetSecurityGroups    = "unableToGetSecurityGroups"
	errUnableToCreateENI         = "unable to create ENI"
	unableToCreateENI            = "unableToCreateENI"
	errUnableToAttachENI         = "unable to attach ENI"
	unableToAttachENI            = "unableToAttachENI"
	unableToFindSubnet           = "unableToFindSubnet"
)

const (
	maxENIIPCreate = 10

	maxENIPerNode = 50
)

type ipamNodeActions interface {
	InstanceID() string
}

type Node struct {
	// node contains the general purpose fields of a node
	node ipamNodeActions

	// mutex protects members below this field
	mutex lock.RWMutex

	// enis is the list of ENIs attached to the node indexed by ENI ID.
	// Protected by Node.mutex.
	enis map[string]eniTypes.ENI

	// k8sObj is the CiliumNode custom resource representing the node
	k8sObj *v2.CiliumNode

	// manager is the ecs node manager responsible for this node
	manager *InstancesManager

	// instanceID of the node
	instanceID string
}

// UpdatedNode is called when an update to the CiliumNode is received.
func (n *Node) UpdatedNode(obj *v2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.k8sObj = obj
}

// PopulateStatusFields fills in the status field of the CiliumNode custom
// resource with ENI specific information
func (n *Node) PopulateStatusFields(resource *v2.CiliumNode) {
	resource.Status.AlibabaCloud.ENIs = map[string]eniTypes.ENI{}

	n.manager.ForeachInstance(n.node.InstanceID(),
		func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			if ok {
				resource.Status.AlibabaCloud.ENIs[interfaceID] = *e.DeepCopy()
			}
			return nil
		})

	return
}

// CreateInterface creates an additional interface with the instance and
// attaches it to the instance as specified by the CiliumNode. neededAddresses
// of secondary IPs are assigned to the interface up to the maximum number of
// addresses as allowed by the instance.
func (n *Node) CreateInterface(ctx context.Context, allocation *ipam.AllocationAction, scopedLog *logrus.Entry) (int, string, error) {
	l, limitsAvailable := n.getLimits()
	if !limitsAvailable {
		return 0, unableToDetermineLimits, fmt.Errorf(errUnableToDetermineLimits)
	}

	n.mutex.RLock()
	resource := *n.k8sObj
	n.mutex.RUnlock()

	// Must allocate secondary ENI IPs as needed, up to ENI instance limit
	toAllocate := math.IntMin(allocation.MaxIPsToAllocate, l.IPv4)
	toAllocate = math.IntMin(maxENIIPCreate, toAllocate) // in first alloc no more than 10
	// Validate whether request has already been fulfilled in the meantime
	if toAllocate == 0 {
		return 0, "", nil
	}

	bestSubnet := n.manager.FindOneVSwitch(resource.Spec.AlibabaCloud, toAllocate)
	if bestSubnet == nil {
		return 0,
			unableToFindSubnet,
			fmt.Errorf(
				"no matching vSwitch available for interface creation (VPC=%s AZ=%s SubnetTags=%s",
				resource.Spec.AlibabaCloud.VPCID,
				resource.Spec.AlibabaCloud.AvailabilityZone,
				resource.Spec.AlibabaCloud.VSwitchTags,
			)
	}
	allocation.PoolID = ipamTypes.PoolID(bestSubnet.ID)

	securityGroupIDs, err := n.getSecurityGroupIDs(ctx, resource.Spec.AlibabaCloud)
	if err != nil {
		return 0,
			unableToGetSecurityGroups,
			fmt.Errorf("%s %s", errUnableToGetSecurityGroups, err)
	}

	scopedLog = scopedLog.WithFields(logrus.Fields{
		"securityGroupIDs": securityGroupIDs,
		"vSwitchID":        bestSubnet.ID,
		"toAllocate":       toAllocate,
	})
	scopedLog.Info("No more IPs available, creating new ENI")

	instanceID := n.node.InstanceID()
	n.mutex.Lock()
	defer n.mutex.Unlock()
	index, err := n.allocENIIndex()
	if err != nil {
		scopedLog.WithField("instanceID", instanceID).Error(err)
		return 0, "", err
	}
	eniID, eni, err := n.manager.api.CreateNetworkInterface(ctx, toAllocate-1, bestSubnet.ID, securityGroupIDs,
		utils.FillTagWithENIIndex(map[string]string{}, index))
	if err != nil {
		return 0, unableToCreateENI, fmt.Errorf("%s %s", errUnableToCreateENI, err)
	}

	scopedLog = scopedLog.WithField(fieldENIID, eniID)
	scopedLog.Info("Created new ENI")

	if bestSubnet.CIDR != nil {
		eni.VSwitch.CIDRBlock = bestSubnet.CIDR.String()
	}

	err = n.manager.api.AttachNetworkInterface(ctx, instanceID, eniID)
	if err != nil {
		err2 := n.manager.api.DeleteNetworkInterface(ctx, eniID)
		if err2 != nil {
			scopedLog.Errorf("Failed to release ENI after failure to attach, %s", err2.Error())
		}
		return 0, unableToAttachENI, fmt.Errorf("%s %s", errUnableToAttachENI, err)
	}
	_, err = n.manager.api.WaitENIAttached(ctx, eniID)
	if err != nil {
		err2 := n.manager.api.DeleteNetworkInterface(ctx, eniID)
		if err2 != nil {
			scopedLog.Errorf("Failed to release ENI after failure to attach, %s", err2.Error())
		}
		return 0, unableToAttachENI, fmt.Errorf("%s %s", errUnableToAttachENI, err)
	}

	n.enis[eniID] = *eni
	scopedLog.Info("Attached ENI to instance")

	// Add the information of the created ENI to the instances manager
	n.manager.UpdateENI(instanceID, eni)
	return toAllocate, "", nil
}

// ResyncInterfacesAndIPs is called to retrieve and ENIs and IPs as known to
// the AlibabaCloud API and return them
func (n *Node) ResyncInterfacesAndIPs(ctx context.Context, scopedLog *logrus.Entry) (available ipamTypes.AllocationMap, stats stats.InterfaceStats, err error) {
	limits, limitsAvailable := n.getLimits()
	if !limitsAvailable {
		return nil, stats, fmt.Errorf(errUnableToDetermineLimits)
	}

	// During preparation of IP allocations, the primary NIC is not considered
	// for allocation, so we don't need to consider it for capacity calculation.
	stats.NodeCapacity = limits.IPv4 * (limits.Adapters - 1)

	instanceID := n.node.InstanceID()
	available = ipamTypes.AllocationMap{}

	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.enis = map[string]eniTypes.ENI{}

	n.manager.ForeachInstance(instanceID,
		func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			if !ok {
				return nil
			}

			n.enis[e.NetworkInterfaceID] = *e
			if e.Type == eniTypes.ENITypePrimary {
				return nil
			}

			// We exclude all "primary" IPs from the capacity.
			primaryAllocated := 0
			for _, ip := range e.PrivateIPSets {
				if ip.Primary {
					primaryAllocated++
				}
			}
			stats.NodeCapacity -= primaryAllocated

			availableOnENI := math.IntMax(limits.IPv4-len(e.PrivateIPSets), 0)
			if availableOnENI > 0 {
				stats.RemainingAvailableInterfaceCount++
			}

			for _, ip := range e.PrivateIPSets {
				available[ip.PrivateIpAddress] = ipamTypes.AllocationIP{Resource: e.NetworkInterfaceID}
			}
			return nil
		})
	enis := len(n.enis)

	// An ECS instance has at least one ENI attached, no ENI found implies instance not found.
	if enis == 0 {
		scopedLog.Warning("Instance not found! Please delete corresponding ciliumnode if instance has already been deleted.")
		return nil, stats, fmt.Errorf("unable to retrieve ENIs")
	}

	stats.RemainingAvailableInterfaceCount += limits.Adapters - len(n.enis)
	return available, stats, nil
}

// PrepareIPAllocation returns the number of ENI IPs and interfaces that can be
// allocated/created.
func (n *Node) PrepareIPAllocation(scopedLog *logrus.Entry) (*ipam.AllocationAction, error) {
	l, limitsAvailable := n.getLimits()
	if !limitsAvailable {
		return nil, fmt.Errorf(errUnableToDetermineLimits)
	}
	a := &ipam.AllocationAction{}

	n.mutex.RLock()
	defer n.mutex.RUnlock()

	for key, e := range n.enis {
		if e.Type != eniTypes.ENITypeSecondary {
			continue
		}
		scopedLog.WithFields(logrus.Fields{
			fieldENIID:  e.NetworkInterfaceID,
			"ipv4Limit": l.IPv4,
			"allocated": len(e.PrivateIPSets),
		}).Debug("Considering ENI for allocation")

		// limit
		availableOnENI := math.IntMax(l.IPv4-len(e.PrivateIPSets), 0)
		if availableOnENI <= 0 {
			continue
		} else {
			a.InterfaceCandidates++
		}

		scopedLog.WithFields(logrus.Fields{
			fieldENIID:       e.NetworkInterfaceID,
			"availableOnENI": availableOnENI,
		}).Debug("ENI has IPs available")

		if subnet := n.manager.GetVSwitch(e.VSwitch.VSwitchID); subnet != nil {
			if subnet.AvailableAddresses > 0 && a.InterfaceID == "" {
				scopedLog.WithFields(logrus.Fields{
					"vSwitchID":          e.VSwitch.VSwitchID,
					"availableAddresses": subnet.AvailableAddresses,
				}).Debug("Subnet has IPs available")

				a.InterfaceID = key
				a.PoolID = ipamTypes.PoolID(subnet.ID)
				a.AvailableForAllocation = math.IntMin(subnet.AvailableAddresses, availableOnENI)
			}
		}
	}
	a.EmptyInterfaceSlots = l.Adapters - len(n.enis)
	return a, nil
}

// AllocateIPs performs the ENI allocation operation
func (n *Node) AllocateIPs(ctx context.Context, a *ipam.AllocationAction) error {
	_, err := n.manager.api.AssignPrivateIPAddresses(ctx, a.InterfaceID, a.AvailableForAllocation)
	return err
}

// PrepareIPRelease prepares the release of ENI IPs.
func (n *Node) PrepareIPRelease(excessIPs int, scopedLog *logrus.Entry) *ipam.ReleaseAction {
	r := &ipam.ReleaseAction{}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	// Iterate over ENIs on this node, select the ENI with the most
	// addresses available for release
	for key, e := range n.enis {
		if e.Type != eniTypes.ENITypeSecondary {
			continue
		}
		scopedLog.WithFields(logrus.Fields{
			fieldENIID:     e.NetworkInterfaceID,
			"numAddresses": len(e.PrivateIPSets),
		}).Debug("Considering ENI for IP release")

		// Count free IP addresses on this ENI
		ipsOnENI := n.k8sObj.Status.AlibabaCloud.ENIs[e.NetworkInterfaceID].PrivateIPSets
		freeIpsOnENI := []string{}
		for _, ip := range ipsOnENI {
			// exclude primary IPs
			if ip.Primary {
				continue
			}
			_, ipUsed := n.k8sObj.Status.IPAM.Used[ip.PrivateIpAddress]
			if !ipUsed {
				freeIpsOnENI = append(freeIpsOnENI, ip.PrivateIpAddress)
			}
		}
		freeOnENICount := len(freeIpsOnENI)

		if freeOnENICount <= 0 {
			continue
		}

		scopedLog.WithFields(logrus.Fields{
			fieldENIID:       e.NetworkInterfaceID,
			"excessIPs":      excessIPs,
			"freeOnENICount": freeOnENICount,
		}).Debug("ENI has unused IPs that can be released")
		maxReleaseOnENI := math.IntMin(freeOnENICount, excessIPs)

		r.InterfaceID = key
		r.PoolID = ipamTypes.PoolID(e.VPC.VPCID)
		r.IPsToRelease = freeIpsOnENI[:maxReleaseOnENI]
	}

	return r
}

// ReleaseIPs performs the ENI IP release operation
func (n *Node) ReleaseIPs(ctx context.Context, r *ipam.ReleaseAction) error {
	return n.manager.api.UnassignPrivateIPAddresses(ctx, r.InterfaceID, r.IPsToRelease)
}

// GetMaximumAllocatableIPv4 returns the maximum amount of IPv4 addresses
// that can be allocated to the instance
func (n *Node) GetMaximumAllocatableIPv4() int {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	// Retrieve l for the instance type
	l, limitsAvailable := n.getLimitsLocked()
	if !limitsAvailable {
		return 0
	}

	// Return the maximum amount of IP addresses allocatable on the instance
	// reserve Primary eni
	return (l.Adapters - 1) * l.IPv4
}

// GetMinimumAllocatableIPv4 returns the minimum amount of IPv4 addresses that
// must be allocated to the instance.
func (n *Node) GetMinimumAllocatableIPv4() int {
	return defaults.IPAMPreAllocation
}

func (n *Node) loggerLocked() *logrus.Entry {
	if n == nil || n.instanceID == "" {
		return log
	}

	return log.WithField("instanceID", n.instanceID)
}

func (n *Node) IsPrefixDelegated() bool {
	return false
}

func (n *Node) GetUsedIPWithPrefixes() int {
	if n.k8sObj == nil {
		return 0
	}
	return len(n.k8sObj.Status.IPAM.Used)
}

// getLimits returns the interface and IP limits of this node
func (n *Node) getLimits() (ipamTypes.Limits, bool) {
	n.mutex.RLock()
	l, b := n.getLimitsLocked()
	n.mutex.RUnlock()
	return l, b
}

// getLimitsLocked is the same function as getLimits, but assumes the n.mutex
// is read locked.
func (n *Node) getLimitsLocked() (ipamTypes.Limits, bool) {
	return limits.Get(n.k8sObj.Spec.AlibabaCloud.InstanceType)
}

func (n *Node) getSecurityGroupIDs(ctx context.Context, eniSpec eniTypes.Spec) ([]string, error) {
	// ENI must have at least one security group
	// 1. use security group defined by user
	// 2. use security group used by primary ENI (eth0)

	if len(eniSpec.SecurityGroups) > 0 {
		return eniSpec.SecurityGroups, nil
	}

	if len(eniSpec.SecurityGroupTags) > 0 {
		securityGroups := n.manager.FindSecurityGroupByTags(eniSpec.VPCID, eniSpec.SecurityGroupTags)
		if len(securityGroups) == 0 {
			n.loggerLocked().WithFields(logrus.Fields{
				"vpcID": eniSpec.VPCID,
				"tags":  eniSpec.SecurityGroupTags,
			}).Warn("No security groups match required VPC ID and tags, using primary ENI's security groups")
		} else {
			groups := make([]string, 0, len(securityGroups))
			for _, secGroup := range securityGroups {
				groups = append(groups, secGroup.ID)
			}
			return groups, nil
		}
	}

	var securityGroups []string

	n.manager.ForeachInstance(n.node.InstanceID(),
		func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			if ok && e.Type == eniTypes.ENITypePrimary {
				securityGroups = append(securityGroups, e.SecurityGroupIDs...)
			}
			return nil
		})

	if len(securityGroups) <= 0 {
		return nil, fmt.Errorf("failed to get security group ids")
	}

	return securityGroups, nil
}

// allocENIIndex will alloc an monotonically increased index for each ENI on this instance.
// The index generated the first time this ENI is created, and stored in ENI.Tags.
func (n *Node) allocENIIndex() (int, error) {
	// alloc index for each created ENI
	used := make([]bool, maxENIPerNode)
	for _, v := range n.enis {
		index := utils.GetENIIndexFromTags(v.Tags)
		if index > maxENIPerNode || index < 0 {
			return 0, fmt.Errorf("ENI index(%d) is out of range", index)
		}
		used[index] = true
	}
	// ECS has at least 1 ENI, 0 is reserved for eth0
	i := 1
	for ; i < maxENIPerNode; i++ {
		if !used[i] {
			break
		}
	}
	return i, nil
}
