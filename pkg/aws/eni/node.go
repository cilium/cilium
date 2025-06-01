// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2017 Lyft, Inc.

package eni

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go"

	"github.com/cilium/cilium/pkg/aws/ec2"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipam/stats"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// maxAttachRetries is the maximum number of attachment retries
	maxAttachRetries = 5

	getMaximumAllocatableIPv4FailureWarningStr = "maximum allocatable ipv4 addresses will be 0 (unlimited)" +
		" this could lead to ip allocation overflows if the max-allocate flag is not set"
)

type ipamNodeActions interface {
	IsPrefixDelegationEnabled() bool
	InstanceID() string
	Ops() ipam.NodeOperations
	SetRunning(bool)
	UpdatedResource(*v2.CiliumNode) bool
}

// Node represents a Kubernetes node running Cilium with an associated
// CiliumNode custom resource
type Node struct {
	rootLogger *slog.Logger
	logger     atomic.Pointer[slog.Logger]
	// node contains the general purpose fields of a node
	node ipamNodeActions

	// mutex protects members below this field
	mutex lock.RWMutex

	// enis is the list of ENIs attached to the node indexed by ENI ID.
	// Protected by Node.mutex.
	enis map[string]eniTypes.ENI

	// k8sObj is the CiliumNode custom resource representing the node
	k8sObj *v2.CiliumNode

	// manager is the EC2 node manager responsible for this node
	manager *InstancesManager

	// instanceID of the node
	instanceID string
}

// NewNode returns a new Node
func NewNode(node *ipam.Node, k8sObj *v2.CiliumNode, manager *InstancesManager) *Node {
	n := &Node{
		rootLogger: manager.logger,
		node:       node,
		k8sObj:     k8sObj,
		manager:    manager,
		instanceID: node.InstanceID(),
	}
	n.updateLogger()
	n.logger.Store(n.rootLogger.With())
	return n
}

// UpdatedNode is called when an update to the CiliumNode is received.
func (n *Node) UpdatedNode(obj *v2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.k8sObj = obj
}

func (n *Node) updateLogger() {
	if n == nil || n.instanceID == "" {
		return
	}

	n.logger.Store(n.rootLogger.With(
		logfields.InstanceID, n.instanceID,
	))
}

// PopulateStatusFields fills in the status field of the CiliumNode custom
// resource with ENI specific information
func (n *Node) PopulateStatusFields(k8sObj *v2.CiliumNode) {
	k8sObj.Status.ENI.ENIs = map[string]eniTypes.ENI{}

	n.manager.ForeachInstance(n.node.InstanceID(),
		func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			if ok {
				k8sObj.Status.ENI.ENIs[interfaceID] = *e.DeepCopy()
			}
			return nil
		})
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
	limit, ok := n.manager.limitsGetter.Get(n.k8sObj.Spec.ENI.InstanceType)
	if !ok {
		n.logger.Load().Debug("Instance type not found in limits packages",
			logfields.InstanceType, n.k8sObj.Spec.ENI.InstanceType,
		)
	}
	return limit, ok
}

// PrepareIPRelease prepares the release of ENI IPs.
func (n *Node) PrepareIPRelease(excessIPs int, scopedLog *slog.Logger) *ipam.ReleaseAction {
	r := &ipam.ReleaseAction{}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	// Needs to be sorted for selecting the same ENI to release IPs from
	// when more than one ENI qualifies for release.
	// Iterate over ENIs on this node, select the ENI with the most
	// addresses available for release
	for _, eniId := range slices.Sorted(maps.Keys(n.enis)) {
		e := n.enis[eniId]

		// IP release for prefixes is not currently supported. Will skip releasing from this ENI
		if len(e.Prefixes) > 0 {
			continue
		}
		scopedLog.Debug(
			"Considering ENI for IP release",
			fieldEniID, e.ID,
			logfields.NeedIndex, *n.k8sObj.Spec.ENI.FirstInterfaceIndex,
			logfields.Index, e.Number,
			logfields.NumAddresses, len(e.Addresses),
		)

		if e.IsExcludedBySpec(n.k8sObj.Spec.ENI) {
			continue
		}

		// Count free IP addresses on this ENI
		ipsOnENI := n.k8sObj.Status.ENI.ENIs[e.ID].Addresses
		freeIpsOnENI := []string{}
		for _, ip := range ipsOnENI {
			_, ipUsed := n.k8sObj.Status.IPAM.Used[ip]
			// exclude primary IPs
			if !ipUsed && ip != e.IP {
				freeIpsOnENI = append(freeIpsOnENI, ip)
			}
		}
		freeOnENICount := len(freeIpsOnENI)

		if freeOnENICount <= 0 {
			continue
		}

		scopedLog.Debug(
			"ENI has unused IPs that can be released",
			fieldEniID, e.ID,
			logfields.ExcessIPs, excessIPs,
			logfields.FreeOnENICount, freeOnENICount,
		)
		maxReleaseOnENI := min(freeOnENICount, excessIPs)

		firstENIWithFreeIPFound := r.IPsToRelease == nil
		eniWithMoreFreeIPsFound := maxReleaseOnENI > len(r.IPsToRelease)
		// Select the ENI with the most addresses available for release
		if firstENIWithFreeIPFound || eniWithMoreFreeIPsFound {
			r.InterfaceID = eniId
			r.PoolID = ipamTypes.PoolID(e.Subnet.ID)
			r.IPsToRelease = freeIpsOnENI[:maxReleaseOnENI]
		}
	}

	return r
}

// ReleaseIPs performs the ENI IP release operation
func (n *Node) ReleaseIPs(ctx context.Context, r *ipam.ReleaseAction) error {
	if err := n.manager.api.UnassignPrivateIpAddresses(ctx, r.InterfaceID, r.IPsToRelease); err != nil {
		return err
	}

	n.manager.RemoveIPsFromENI(n.node.InstanceID(), r.InterfaceID, r.IPsToRelease)
	return nil

}

// PrepareIPAllocation returns the number of ENI IPs and interfaces that can be
// allocated/created.
func (n *Node) PrepareIPAllocation(scopedLog *slog.Logger) (a *ipam.AllocationAction, err error) {
	limits, limitsAvailable := n.getLimits()
	if !limitsAvailable {
		return nil, errors.New(errUnableToDetermineLimits)
	}

	a = &ipam.AllocationAction{}

	n.mutex.RLock()
	defer n.mutex.RUnlock()

	for key, e := range n.enis {
		scopedLog.Debug(
			"Considering ENI for allocation",
			fieldEniID, e.ID,
			logfields.NeedIndex, *n.k8sObj.Spec.ENI.FirstInterfaceIndex,
			logfields.Index, e.Number,
			logfields.AddressLimit, limits.IPv4,
			logfields.NumAddresses, len(e.Addresses),
		)

		if e.IsExcludedBySpec(n.k8sObj.Spec.ENI) {
			scopedLog.Debug(
				"ENI is excluded by spec",
				fieldEniID, e.ID,
			)
			continue
		}

		_, effectiveLimits := n.getEffectiveIPLimits(&e, limits.IPv4)
		availableOnENI := max(effectiveLimits-len(e.Addresses), 0)
		if availableOnENI <= 0 {
			continue
		} else {
			a.IPv4.InterfaceCandidates++
		}

		scopedLog.Debug(
			"ENI has IPs available",
			fieldEniID, e.ID,
			logfields.AvailableOnENI, availableOnENI,
		)

		if subnet := n.manager.GetSubnet(e.Subnet.ID); subnet != nil {
			if subnet.AvailableAddresses > 0 && a.InterfaceID == "" {
				scopedLog.Debug(
					"Subnet has IPs available",
					logfields.SubnetID, e.Subnet.ID,
					logfields.AvailableAddresses, subnet.AvailableAddresses,
				)

				a.InterfaceID = key
				a.PoolID = ipamTypes.PoolID(subnet.ID)
				a.IPv4.AvailableForAllocation = min(subnet.AvailableAddresses, availableOnENI)
			}
		}
	}
	a.EmptyInterfaceSlots = limits.Adapters - len(n.enis)

	return
}

// isSubnetAtPrefixCapacity parses error from AWS SDK to understand if the subnet is out of capacity for /28 prefixes.
func isSubnetAtPrefixCapacity(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == ec2.InsufficientPrefixesInSubnetStr ||
			(apiErr.ErrorCode() == ec2.InvalidParameterValueStr &&
				strings.Contains(apiErr.ErrorMessage(), ec2.SubnetFullErrMsgStr))
	}
	return false
}

// AllocateIPs performs the ENI allocation operation
func (n *Node) AllocateIPs(ctx context.Context, a *ipam.AllocationAction) error {
	// Check if the interface to allocate on is prefix delegated
	n.mutex.RLock()
	isPrefixDelegated := n.node.Ops().IsPrefixDelegated()
	n.mutex.RUnlock()

	if isPrefixDelegated {
		numPrefixes := ip.PrefixCeil(a.IPv4.AvailableForAllocation, option.ENIPDBlockSizeIPv4)
		err := n.manager.api.AssignENIPrefixes(ctx, a.InterfaceID, int32(numPrefixes))
		if !isSubnetAtPrefixCapacity(err) {
			return err
		}
		// Subnet might be out of available /28 prefixes, but /32 IP addresses might be available.
		// We should attempt to allocate /32 IPs.
		n.logger.Load().Warn(
			"Subnet might be out of prefixes, Cilium will not allocate prefixes on this node anymore",
			logfields.Node, n.k8sObj.Name,
		)
	}
	assignedIPs, err := n.manager.api.AssignPrivateIpAddresses(ctx, a.InterfaceID, int32(a.IPv4.AvailableForAllocation))
	if err != nil {
		return err
	}
	n.manager.AddIPsToENI(n.node.InstanceID(), a.InterfaceID, assignedIPs)
	return nil
}

func (n *Node) AllocateStaticIP(ctx context.Context, staticIPTags ipamTypes.Tags) (string, error) {
	return n.manager.api.AssociateEIP(ctx, n.node.InstanceID(), staticIPTags)
}

func (n *Node) getSecurityGroupIDs(ctx context.Context, eniSpec eniTypes.ENISpec) ([]string, error) {
	// 1. check explicit security groups associations via checking Spec.ENI.SecurityGroups
	// 2. check if Spec.ENI.SecurityGroupTags is passed and if so filter by those
	// 3. if 1 and 2 give no results derive the security groups from eth0

	if len(eniSpec.SecurityGroups) > 0 {
		return eniSpec.SecurityGroups, nil
	}

	if len(eniSpec.SecurityGroupTags) > 0 {
		securityGroups := n.manager.FindSecurityGroupByTags(eniSpec.VpcID, eniSpec.SecurityGroupTags)
		if len(securityGroups) == 0 {
			n.logger.Load().Warn(
				"No security groups match required vpc id and tags, using eth0 security groups",
				logfields.VPCID, eniSpec.VpcID,
				logfields.Tags, eniSpec.SecurityGroupTags,
			)
		} else {
			groups := make([]string, 0, len(securityGroups))
			for _, secGroup := range securityGroups {
				groups = append(groups, secGroup.ID)
			}
			slices.Sort(groups)
			return groups, nil
		}
	}

	var securityGroups []string

	n.manager.ForeachInstance(n.node.InstanceID(),
		func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			if ok && e.Number == 0 {
				securityGroups = make([]string, len(e.SecurityGroups))
				copy(securityGroups, e.SecurityGroups)
			}
			return nil
		})

	if securityGroups == nil {
		return nil, errors.New("failed to get security group ids")
	}

	slices.Sort(securityGroups)

	return securityGroups, nil
}

func (n *Node) errorInstanceNotRunning(err error) (notRunning bool) {
	// This is handling the special case when an instance has been
	// terminated but the grace period has delayed the Kubernetes node
	// deletion event to not have been sent out yet. The next ENI resync
	// will cause the instance to be marked as inactive.
	if strings.Contains(err.Error(), "is not 'running'") {
		n.node.SetRunning(false)
		n.logger.Load().Info("Marking node as not running")
	}
	return
}

func isAttachmentIndexConflict(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == ec2.InvalidParameterValueStr &&
			strings.Contains(apiErr.ErrorMessage(), "interface attached at device")
	}
	return false
}

// indexExists returns true if the specified index is occupied by an ENI in the
// slice of ENIs
func indexExists(enis map[string]eniTypes.ENI, index int32) bool {
	for _, e := range enis {
		if e.Number == int(index) {
			return true
		}
	}
	return false
}

// findNextIndex returns the next available index with the provided index being
// the first candidate. When calling this function, ensure that the mutex is
// not held as this function read-locks the mutex to protect access to
// `n.enis`.
func (n *Node) findNextIndex(index int32) int32 {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	for indexExists(n.enis, index) {
		index++
	}
	return int32(index)
}

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
	unableToMarkENIForDeletion   = "unableToMarkENIForDeletion"
	unableToFindSubnet           = "unableToFindSubnet"
)

// CreateInterface creates an additional interface with the instance and
// attaches it to the instance as specified by the CiliumNode. neededAddresses
// of secondary IPs are assigned to the interface up to the maximum number of
// addresses as allowed by the instance.
func (n *Node) CreateInterface(ctx context.Context, allocation *ipam.AllocationAction, scopedLog *slog.Logger) (int, string, error) {
	limits, limitsAvailable := n.getLimits()
	if !limitsAvailable {
		return 0, unableToDetermineLimits, errors.New(errUnableToDetermineLimits)
	}

	n.mutex.RLock()
	resource := *n.k8sObj
	isPrefixDelegated := n.node.Ops().IsPrefixDelegated()
	n.mutex.RUnlock()

	subnet := n.findSuitableSubnet(resource.Spec.ENI, limits)
	if subnet == nil {
		return 0,
			unableToFindSubnet,
			fmt.Errorf(
				"No matching subnet available for interface creation (VPC=%s AZ=%s SubnetIDs=%v SubnetTags=%s)",
				resource.Spec.ENI.VpcID,
				resource.Spec.ENI.AvailabilityZone,
				resource.Spec.ENI.SubnetIDs,
				resource.Spec.ENI.SubnetTags,
			)
	}
	allocation.PoolID = ipamTypes.PoolID(subnet.ID)

	securityGroupIDs, err := n.getSecurityGroupIDs(ctx, resource.Spec.ENI)
	if err != nil {
		return 0,
			unableToGetSecurityGroups,
			fmt.Errorf("%s: %w", errUnableToGetSecurityGroups, err)
	}

	desc := "Cilium-CNI (" + n.node.InstanceID() + ")"

	// Must allocate secondary ENI IPs as needed, up to ENI instance limit - 1 (reserve 1 for primary IP)
	toAllocate := min(allocation.IPv4.MaxIPsToAllocate, limits.IPv4-1)
	// Validate whether request has already been fulfilled in the meantime
	if toAllocate == 0 {
		return 0, "", nil
	}

	index := n.findNextIndex(int32(*resource.Spec.ENI.FirstInterfaceIndex))

	scopedLog = scopedLog.With(
		logfields.SecurityGroupIDs, securityGroupIDs,
		logfields.SubnetID, subnet.ID,
		logfields.Addresses, toAllocate,
		logfields.IsPrefixDelegated, isPrefixDelegated,
	)
	scopedLog.Info("No more IPs available, creating new ENI")

	eniID, eni, err := n.manager.api.CreateNetworkInterface(ctx, int32(toAllocate), subnet.ID, desc, securityGroupIDs, isPrefixDelegated)
	if err != nil {
		if isPrefixDelegated && isSubnetAtPrefixCapacity(err) {
			// Subnet might be out of available /28 prefixes, but /32 IP addresses might be available.
			// We should attempt to allocate /32 IPs.
			scopedLog.Warn(
				"Subnet might be out of prefixes, Cilium will not allocate prefixes on this node anymore",
				logfields.Node, n.k8sObj.Name,
			)
			eniID, eni, err = n.manager.api.CreateNetworkInterface(ctx, int32(toAllocate), subnet.ID, desc, securityGroupIDs, false)
		}
		if err != nil {
			return 0, unableToCreateENI, fmt.Errorf("%s: %w", errUnableToCreateENI, err)
		}
	}

	scopedLog.Debug("ENI after initial creation", logfields.ENI, eni)

	scopedLog.Info("Created new ENI", fieldEniID, eniID)

	if subnet.CIDR.IsValid() {
		eni.Subnet.CIDR = subnet.CIDR.String()
	}

	var attachmentID string
	for range maxAttachRetries {
		attachmentID, err = n.manager.api.AttachNetworkInterface(ctx, index, n.node.InstanceID(), eniID)

		// The index is already in use, this can happen if the local
		// list of ENIs is oudated.  Retry the attachment to avoid
		// having to delete the ENI
		if !isAttachmentIndexConflict(err) {
			break
		}

		index = n.findNextIndex(index + 1)
	}

	if err != nil {
		delErr := n.manager.api.DeleteNetworkInterface(ctx, eniID)
		if delErr != nil {
			scopedLog.Warn(
				"Unable to undo ENI creation after failure to attach",
				logfields.Error, delErr,
			)
		}

		if n.errorInstanceNotRunning(err) {
			return toAllocate, "", nil
		}

		return 0,
			unableToAttachENI,
			fmt.Errorf("%s at index %d: %w", errUnableToAttachENI, index, err)
	}

	eni.Number = int(index)

	scopedLog.Info("Attached ENI to instance",
		logfields.AttachmentID, attachmentID,
		logfields.Index, index,
	)

	if resource.Spec.ENI.DeleteOnTermination == nil || *resource.Spec.ENI.DeleteOnTermination {
		// We have an attachment ID from the last API, which lets us mark the
		// interface as delete on termination
		err = n.manager.api.ModifyNetworkInterface(ctx, eniID, attachmentID, true)
		if err != nil {
			delErr := n.manager.api.DeleteNetworkInterface(ctx, eniID)
			if delErr != nil {
				scopedLog.Warn(
					"Unable to undo ENI creation after failure to attach",
					logfields.Error, delErr,
					logfields.AttachmentID, attachmentID,
					logfields.Index, index,
				)
			}

			if n.errorInstanceNotRunning(err) {
				return toAllocate, "", nil
			}

			return 0, unableToMarkENIForDeletion, fmt.Errorf("unable to mark ENI for deletion on termination: %w", err)
		}
	}

	// Add the information of the created ENI to the instances manager
	n.manager.UpdateENI(n.node.InstanceID(), eni)
	return toAllocate, "", nil
}

// ResyncInterfacesAndIPs is called to retrieve and ENIs and IPs as known to
// the EC2 API and return them
func (n *Node) ResyncInterfacesAndIPs(ctx context.Context, scopedLog *slog.Logger) (
	available ipamTypes.AllocationMap,
	stats stats.InterfaceStats,
	err error) {
	limits, limitsAvailable := n.getLimits()
	if !limitsAvailable {
		return nil, stats, ipam.LimitsNotFound{}
	}

	// n.node does not need to be protected by n.mutex as it is only written to
	// upon creation of `n`
	instanceID := n.node.InstanceID()
	available = ipamTypes.AllocationMap{}

	n.mutex.Lock()
	n.enis = map[string]eniTypes.ENI{}

	// 1. This calculates the base interface effective limit on this Node, given:
	// 		* IPAM Prefix Delegation
	// 		* Node Spec usePrimaryAddress being enabled
	//
	_, stats.NodeCapacity = n.getEffectiveIPLimits(nil, limits.IPv4)

	// 2. The base node limit is the number of adapters multiplied by the instances IP limit.
	//
	// Note: This may be modified in step(s) 3, where:
	// * Any leftover additional prefix delegated room will be added to this total.
	// * Any excluded interfaces will be subtracted from this total.
	stats.NodeCapacity *= limits.Adapters

	n.manager.ForeachInstance(instanceID,
		func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			if !ok {
				return nil
			}

			n.enis[e.ID] = *e

			// 3. Finally, we iterate any already existing interfaces and add on any extra
			//		capacity to account for leftover prefix delegated /28 ip slots.
			leftoverPrefixCapcity, effectiveLimits := n.getEffectiveIPLimits(e, limits.IPv4)
			if e.IsExcludedBySpec(n.k8sObj.Spec.ENI) {
				// If this ENI is excluded by the CN Spec, we remove it from the total
				// capacity.
				stats.NodeCapacity -= effectiveLimits
				return nil
			} else {
				stats.NodeCapacity += leftoverPrefixCapcity
			}

			availableOnENI := max(effectiveLimits-len(e.Addresses), 0)
			if availableOnENI > 0 {
				stats.RemainingAvailableInterfaceCount++
			}

			for _, ip := range e.Addresses {
				available[ip] = ipamTypes.AllocationIP{Resource: e.ID}
			}

			// If the primary ENI has a public IP, we store it
			if e.Number == 0 && e.PublicIP != "" {
				stats.AssignedStaticIP = e.PublicIP
			}

			return nil
		})
	enis := len(n.enis)
	n.mutex.Unlock()

	// An ec2 instance has at least one ENI attached, no ENI found implies instance not found.
	if enis == 0 {
		scopedLog.Warn("Instance not found! Please delete corresponding ciliumnode if instance has already been deleted.")
		return nil, stats, fmt.Errorf("unable to retrieve ENIs")
	}

	stats.RemainingAvailableInterfaceCount += limits.Adapters - len(n.enis)
	return available, stats, nil
}

// GetMaximumAllocatableIPv4 returns the maximum amount of IPv4 addresses
// that can be allocated to the instance
func (n *Node) GetMaximumAllocatableIPv4() int {
	if n == nil {
		return 0
	}

	n.mutex.RLock()
	defer n.mutex.RUnlock()

	// Retrieve FirstInterfaceIndex from node spec
	if n.k8sObj == nil ||
		n.k8sObj.Spec.ENI.FirstInterfaceIndex == nil {
		n.logger.Load().Warn(
			fmt.Sprintf("Could not determine first interface index, %s", getMaximumAllocatableIPv4FailureWarningStr),
			logfields.FirstInterfaceIndex, "unknown",
		)
		return 0
	}
	firstInterfaceIndex := *n.k8sObj.Spec.ENI.FirstInterfaceIndex

	// Retrieve limits for the instance type
	limits, limitsAvailable := n.getLimitsLocked()
	if !limitsAvailable {
		n.logger.Load().Warn(
			fmt.Sprintf("Could not determined instance limits, %s", getMaximumAllocatableIPv4FailureWarningStr),
			logfields.AdaptersLimit, "unknown",
			logfields.FirstInterfaceIndex, "unknown",
		)
		return 0
	}

	// Validate the amount of adapters is bigger than the configured FirstInterfaceIndex
	if limits.Adapters < firstInterfaceIndex {
		n.logger.Load().Warn(
			fmt.Sprintf("Instance type network adapters limit is lower than the configured FirstInterfaceIndex, %s",
				getMaximumAllocatableIPv4FailureWarningStr),
			logfields.AdaptersLimit, limits.Adapters,
			logfields.FirstInterfaceIndex, firstInterfaceIndex,
		)
		return 0
	}

	// limits.IPv4 contains the primary IP which is not available for allocation
	maxPerInterface := max(limits.IPv4-1, 0)

	if n.IsPrefixDelegated() {
		maxPerInterface = maxPerInterface * option.ENIPDBlockSizeIPv4
	}

	// Return the maximum amount of IP addresses allocatable on the instance
	return (limits.Adapters - firstInterfaceIndex) * maxPerInterface
}

var adviseOperatorFlagOnce sync.Once

// GetMinimumAllocatableIPv4 returns the minimum amount of IPv4 addresses that
// must be allocated to the instance.
func (n *Node) GetMinimumAllocatableIPv4() int {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	minimum := defaults.IPAMPreAllocation

	if n.k8sObj == nil || n.k8sObj.Spec.ENI.FirstInterfaceIndex == nil {
		n.logger.Load().Warn(
			"Could not determine first-interface-index, falling back to default pre-allocate value",
			logfields.AdaptersLimit, "unknown",
			logfields.PreAllocate, minimum,
		)
		return minimum
	}

	index := *n.k8sObj.Spec.ENI.FirstInterfaceIndex

	// In ENI mode, we must adjust the PreAllocate value based on the instance
	// type. An adjustment is necessary when the number of possible IPs
	// corresponding to the instance type limit is smaller than the default
	// PreAllocate value. Otherwise, we fallback to the default PreAllocate.
	//
	// If we don't adjust the PreAllocate value, then it would be impossible to
	// allocate IPs for smaller instance types because the PreAllocate would
	// exceed the maximum possible number of IPs per instance.

	limits, limitsAvailable := n.getLimitsLocked()
	if !limitsAvailable {
		adviseOperatorFlagOnce.Do(func() {
			n.logger.Load().Warn(
				"Unable to find limits for instance type",
				logfields.InstanceType, n.k8sObj.Spec.ENI.InstanceType,
			)
		})

		return minimum
	}

	// We cannot allocate any IPs if this is the case because all the ENIs will
	// be skipped.
	if index >= limits.Adapters {
		return 0
	}

	// limits.IPv4 contains the primary IP which is not available for allocation
	maxPerInterface := max(limits.IPv4-1, 0)

	return min(minimum, (limits.Adapters-index)*maxPerInterface)
}

func (n *Node) isPrefixDelegationEnabled() bool {
	if n.node == nil {
		return false
	}
	return n.node.IsPrefixDelegationEnabled()
}

// IsPrefixDelegated indicates whether prefix delegation can be enabled on a node.
// Currently, mixed usage of secondary IPs and prefixes is not supported. n.mutex
// read lock must be held before calling this method.
func (n *Node) IsPrefixDelegated() bool {
	if !n.isPrefixDelegationEnabled() {
		return false
	}
	// Verify if this node is nitro based
	limits, limitsAvailable := n.getLimitsLocked()
	if !limitsAvailable {
		return false
	}
	// Allocating prefixes is supported only on nitro instances
	if limits.HypervisorType != "nitro" {
		return false
	}
	// Check if this node is allowed to use prefix delegation
	if n.k8sObj.Spec.ENI.DisablePrefixDelegation != nil && aws.ToBool(n.k8sObj.Spec.ENI.DisablePrefixDelegation) {
		return false
	}
	// Verify if all interfaces are prefix delegated. We don't want to enable prefix delegation on nodes that already
	// use secondary IPs.
	for _, eni := range n.enis {
		if len(eni.Addresses) == 0 {
			continue
		}
		if len(eni.Prefixes) == 0 && len(eni.Addresses) > 0 {
			// Ignore primary IP of the ENI
			if len(eni.Addresses) == 1 && eni.Addresses[0] == eni.IP {
				continue
			}
			return false
		}
	}
	return true
}

// GetUsedIPWithPrefixes returns the total number of used IPs on the node including the prefixes allocated.
// A prefix is considered as used if there is at least one allocated IP from that prefix. All IPs from a used prefix
// are included in the count returned.
func (n *Node) GetUsedIPWithPrefixes() int {
	var usedIps int
	eniPrefixes := make(map[string][]netip.Prefix)

	// Populate ENI -> Prefix mapping
	for eniName, eni := range n.k8sObj.Status.ENI.ENIs {
		var prefixes []netip.Prefix
		for _, pfx := range eni.Prefixes {
			ipNet, err := netip.ParsePrefix(pfx)
			if err != nil {
				continue
			}
			prefixes = append(prefixes, ipNet)
		}
		eniPrefixes[eniName] = prefixes
	}
	usedPfx := make(map[netip.Prefix]bool)
	for ip, resource := range n.k8sObj.Status.IPAM.Used {
		// Fetch prefixes on this IP's ENI
		prefixNetworks, exists := eniPrefixes[resource.Resource]
		if !exists {
			continue
		}
		var prefixBased bool
		var pfx netip.Prefix
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		// Check if the IP is from any of the prefixes attached to this ENI
		for _, ipNet := range prefixNetworks {
			if ipNet.Contains(addr) {
				prefixBased = true
				pfx = ipNet
				break
			}
		}
		if prefixBased {
			if !usedPfx[pfx] {
				usedIps = usedIps + option.ENIPDBlockSizeIPv4
				usedPfx[pfx] = true
			}
		} else {
			usedIps++
		}
	}
	return usedIps
}

// getEffectiveIPLimits computing the effective number of available addresses on the ENI
// based on limits (which includes any left over prefix delegation capacity), as well as
// just the left over prefix delegation capacity.
func (n *Node) getEffectiveIPLimits(eni *eniTypes.ENI, limits int) (leftoverPrefixCapacity, effectiveLimits int) {
	// The limits include the primary IP, so we need to take it into account
	// when computing the effective number of available addresses on the ENI.
	effectiveLimits = limits - 1

	// Include the primary IP when UsePrimaryAddress is set to true on ENI spec.
	if n.k8sObj.Spec.ENI.UsePrimaryAddress != nil && *n.k8sObj.Spec.ENI.UsePrimaryAddress {
		effectiveLimits++
	}

	if n.IsPrefixDelegated() {
		effectiveLimits = effectiveLimits * option.ENIPDBlockSizeIPv4
	} else if eni != nil && len(eni.Prefixes) > 0 {
		// If prefix delegation was previously enabled on this node, account for IPs from prefixes
		leftoverPrefixCapacity = len(eni.Prefixes) * (option.ENIPDBlockSizeIPv4 - 1)
		effectiveLimits += leftoverPrefixCapacity
	}
	return leftoverPrefixCapacity, effectiveLimits
}

// findSubnetInSameRouteTableWithNodeSubnet returns the subnet with the most addresses
// that is in the same route table as the node's subnet to make sure the pod traffic
// leaving secondary interfaces will be routed as the primary interface.
func (n *Node) findSubnetInSameRouteTableWithNodeSubnet() *ipamTypes.Subnet {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if n.k8sObj == nil {
		return nil
	}

	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()

	nodeSubnetID := n.k8sObj.Spec.ENI.NodeSubnetID
	var bestSubnet *ipamTypes.Subnet

	for _, routeTable := range n.manager.routeTables {
		if _, ok := routeTable.Subnets[nodeSubnetID]; ok && routeTable.VirtualNetworkID == n.k8sObj.Spec.ENI.VpcID {
			for _, subnetID := range n.k8sObj.Spec.ENI.SubnetIDs {
				if subnetID == nodeSubnetID {
					continue
				}
				if _, ok := routeTable.Subnets[subnetID]; ok {
					subnet := n.manager.subnets[subnetID]
					if bestSubnet == nil || subnet.AvailableAddresses > bestSubnet.AvailableAddresses {
						bestSubnet = subnet
					}
				}
			}
		}
	}

	return bestSubnet
}

// checkSubnetInSameRouteTableWithNodeSubnet checks if the given subnet is in the same route table as the node's subnet
// to make sure the pod traffic leaving secondary interfaces will be routed as the primary interface.
func (n *Node) checkSubnetInSameRouteTableWithNodeSubnet(subnet *ipamTypes.Subnet) bool {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if n.k8sObj == nil {
		return false
	}

	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()

	for _, routeTable := range n.manager.routeTables {
		if _, ok := routeTable.Subnets[n.k8sObj.Spec.ENI.NodeSubnetID]; ok && routeTable.VirtualNetworkID == n.k8sObj.Spec.ENI.VpcID {
			if _, ok := routeTable.Subnets[subnet.ID]; ok {
				return true
			}
		}
	}
	return false
}

func (n *Node) logSubnetRouteTableMismatch(subnet *ipamTypes.Subnet, matchType string) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	if subnet == nil {
		return
	}
	n.logger.Load().Warn(
		fmt.Sprintf("ENI NodeSubnet and %s subnet are not in the same route tables, and you might have unexpected traffic routing", matchType),
		logfields.SubnetID, n.k8sObj.Spec.ENI.NodeSubnetID,
		logfields.SubnetID, subnet.ID,
	)
}

// findSuitableSubnet attempts to find a subnet to allocate an ENI in according to the following heuristic.
//  0. In general, the subnet has to be in the same VPC and match the availability zone of the
//     node. If there are multiple candidates, we choose the subnet with the most addresses
//     available.
//  1. If we have explicit ID or tag constraints, chose a matching subnet. ID constraints take
//     precedence.
//  2. If we have no explicit constraints, try to use the subnet the first ENI of the node was
//     created in, to avoid putting the ENI in a surprising subnet if possible.
//  3. If we can't use the subnet first ENI in, try to use the subnet in the same route table as the node's subnet.
//  4. If none of these work, fall back to just choosing the subnet with the most addresses
//     available.
func (n *Node) findSuitableSubnet(spec eniTypes.ENISpec, limits ipamTypes.Limits) *ipamTypes.Subnet {
	if len(spec.SubnetIDs) > 0 {
		if subnet := n.manager.FindSubnetByIDs(spec.VpcID, spec.AvailabilityZone, spec.SubnetIDs); subnet != nil {
			if !n.checkSubnetInSameRouteTableWithNodeSubnet(subnet) {
				n.logSubnetRouteTableMismatch(subnet, "Specified")
			}
			return subnet
		}
	}

	if len(spec.SubnetTags) > 0 {
		if subnet := n.manager.FindSubnetByTags(spec.VpcID, spec.AvailabilityZone, spec.SubnetTags); subnet != nil {
			if !n.checkSubnetInSameRouteTableWithNodeSubnet(subnet) {
				n.logSubnetRouteTableMismatch(subnet, "Tagged")
			}
			return subnet
		}
	}

	if subnet := n.manager.GetSubnet(spec.NodeSubnetID); subnet != nil && subnet.AvailableAddresses >= limits.IPv4 {
		return subnet
	}

	if subnet := n.findSubnetInSameRouteTableWithNodeSubnet(); subnet != nil {
		return subnet
	}
	if subnet := n.manager.FindSubnetByTags(spec.VpcID, spec.AvailabilityZone, nil); subnet != nil {
		if !n.checkSubnetInSameRouteTableWithNodeSubnet(subnet) {
			n.logSubnetRouteTableMismatch(subnet, "")
		}
		return subnet
	}

	return nil
}
