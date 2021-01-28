// Copyright 2019-2020 Authors of Cilium
// Copyright 2017 Lyft, Inc.
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

package eni

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/smithy-go"
	"github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/aws/eni/limits"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/math"

	"github.com/sirupsen/logrus"
)

const (
	// maxAttachRetries is the maximum number of attachment retries
	maxAttachRetries = 5

	getMaximumAllocatableIPv4FailureWarningStr = "maximum allocatable ipv4 addresses will be 0 (unlimited)" +
		" this could lead to ip allocation overflows if the max-allocate flag is not set"
)

// Node represents a Kubernetes node running Cilium with an associated
// CiliumNode custom resource
type Node struct {
	// node contains the general purpose fields of a node
	node *ipam.Node

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
	return &Node{
		node:       node,
		k8sObj:     k8sObj,
		manager:    manager,
		instanceID: node.InstanceID(),
	}
}

// UpdatedNode is called when an update to the CiliumNode is received.
func (n *Node) UpdatedNode(obj *v2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.k8sObj = obj
}

func (n *Node) loggerLocked() *logrus.Entry {
	if n == nil || n.instanceID == "" {
		return log
	}

	return log.WithField("instanceID", n.instanceID)
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

	return
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
	return limits.Get(n.k8sObj.Spec.ENI.InstanceType)
}

// PrepareIPRelease prepares the release of ENI IPs.
func (n *Node) PrepareIPRelease(excessIPs int, scopedLog *logrus.Entry) *ipam.ReleaseAction {
	r := &ipam.ReleaseAction{}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	// Iterate over ENIs on this node, select the ENI with the most
	// addresses available for release
	for key, e := range n.enis {
		scopedLog.WithFields(logrus.Fields{
			fieldEniID:     e.ID,
			"needIndex":    *n.k8sObj.Spec.ENI.FirstInterfaceIndex,
			"index":        e.Number,
			"numAddresses": len(e.Addresses),
		}).Debug("Considering ENI for IP release")

		if e.Number < *n.k8sObj.Spec.ENI.FirstInterfaceIndex {
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

		scopedLog.WithFields(logrus.Fields{
			fieldEniID:       e.ID,
			"excessIPs":      excessIPs,
			"freeOnENICount": freeOnENICount,
		}).Debug("ENI has unused IPs that can be released")
		maxReleaseOnENI := math.IntMin(freeOnENICount, excessIPs)

		firstENIWithFreeIPFound := r.IPsToRelease == nil
		eniWithMoreFreeIPsFound := maxReleaseOnENI > len(r.IPsToRelease)
		// Select the ENI with the most addresses available for release
		if firstENIWithFreeIPFound || eniWithMoreFreeIPsFound {
			r.InterfaceID = key
			r.PoolID = ipamTypes.PoolID(e.Subnet.ID)
			r.IPsToRelease = freeIpsOnENI[:maxReleaseOnENI]
		}
	}

	return r
}

// ReleaseIPs performs the ENI IP release operation
func (n *Node) ReleaseIPs(ctx context.Context, r *ipam.ReleaseAction) error {
	return n.manager.api.UnassignPrivateIpAddresses(ctx, r.InterfaceID, r.IPsToRelease)
}

// PrepareIPAllocation returns the number of ENI IPs and interfaces that can be
// allocated/created.
func (n *Node) PrepareIPAllocation(scopedLog *logrus.Entry) (a *ipam.AllocationAction, err error) {
	limits, limitsAvailable := n.getLimits()
	if !limitsAvailable {
		return nil, fmt.Errorf("Unable to determine limits")
	}

	a = &ipam.AllocationAction{}

	n.mutex.RLock()
	defer n.mutex.RUnlock()

	for key, e := range n.enis {
		scopedLog.WithFields(logrus.Fields{
			fieldEniID:     e.ID,
			"needIndex":    *n.k8sObj.Spec.ENI.FirstInterfaceIndex,
			"index":        e.Number,
			"addressLimit": limits.IPv4,
			"numAddresses": len(e.Addresses),
		}).Debug("Considering ENI for allocation")

		if e.Number < *n.k8sObj.Spec.ENI.FirstInterfaceIndex {
			continue
		}

		availableOnENI := math.IntMax(limits.IPv4-len(e.Addresses), 0)
		if availableOnENI <= 0 {
			continue
		} else {
			a.AvailableInterfaces++
		}

		scopedLog.WithFields(logrus.Fields{
			fieldEniID:       e.ID,
			"availableOnEni": availableOnENI,
		}).Debug("ENI has IPs available")

		if subnet := n.manager.GetSubnet(e.Subnet.ID); subnet != nil {
			if subnet.AvailableAddresses > 0 && a.InterfaceID == "" {
				scopedLog.WithFields(logrus.Fields{
					"subnetID":           e.Subnet.ID,
					"availableAddresses": subnet.AvailableAddresses,
				}).Debug("Subnet has IPs available")

				a.InterfaceID = key
				a.PoolID = ipamTypes.PoolID(subnet.ID)
				a.AvailableForAllocation = math.IntMin(subnet.AvailableAddresses, availableOnENI)
			}
		}
	}
	a.AvailableInterfaces = limits.Adapters - len(n.enis) + a.AvailableInterfaces

	return
}

// AllocateIPs performs the ENI allocation oepration
func (n *Node) AllocateIPs(ctx context.Context, a *ipam.AllocationAction) error {
	return n.manager.api.AssignPrivateIpAddresses(ctx, a.InterfaceID, int32(a.AvailableForAllocation))
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
			n.loggerLocked().WithFields(logrus.Fields{
				"vpcID": eniSpec.VpcID,
				"tags":  eniSpec.SecurityGroupTags,
			}).Warn("No security groups match required vpc id and tags, using eth0 security groups")
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
			if ok && e.Number == 0 {
				securityGroups = make([]string, len(e.SecurityGroups))
				copy(securityGroups, e.SecurityGroups)
			}
			return nil
		})

	if securityGroups == nil {
		return nil, fmt.Errorf("failed to get security group ids")
	}

	return securityGroups, nil
}

func (n *Node) errorInstanceNotRunning(err error) (notRunning bool) {
	// This is handling the special case when an instance has been
	// terminated but the grace period has delayed the Kubernetes node
	// deletion event to not have been sent out yet. The next ENI resync
	// will cause the instance to be marked as inactive.
	if strings.Contains(err.Error(), "is not 'running'") {
		n.node.SetRunning(false)
		log.Info("Marking node as not running")
	}
	return
}

func isAttachmentIndexConflict(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == "InvalidParameterValue" && strings.Contains(apiErr.ErrorMessage(), "interface attached at device")
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
	errUnableToDetermineLimits    = "unable to determine limits"
	errUnableToGetSecurityGroups  = "unable to get security groups"
	errUnableToCreateENI          = "unable to create ENI"
	errUnableToAttachENI          = "unable to attach ENI"
	errUnableToMarkENIForDeletion = "unable to mark ENI for deletion"
	errUnableToFindSubnet         = "unable to find matching subnet"
)

// CreateInterface creates an additional interface with the instance and
// attaches it to the instance as specified by the CiliumNode. neededAddresses
// of secondary IPs are assigned to the interface up to the maximum number of
// addresses as allowed by the instance.
func (n *Node) CreateInterface(ctx context.Context, allocation *ipam.AllocationAction, scopedLog *logrus.Entry) (int, string, error) {
	limits, limitsAvailable := n.getLimits()
	if !limitsAvailable {
		return 0, errUnableToDetermineLimits, fmt.Errorf(errUnableToDetermineLimits)
	}

	n.mutex.RLock()
	resource := *n.k8sObj
	n.mutex.RUnlock()

	bestSubnet := n.manager.FindSubnetByTags(resource.Spec.ENI.VpcID, resource.Spec.ENI.AvailabilityZone, resource.Spec.ENI.SubnetTags)
	if bestSubnet == nil {
		return 0,
			errUnableToFindSubnet,
			fmt.Errorf(
				"No matching subnet available for interface creation (VPC=%s AZ=%s SubnetTags=%s",
				resource.Spec.ENI.VpcID,
				resource.Spec.ENI.AvailabilityZone,
				resource.Spec.ENI.SubnetTags,
			)
	}

	securityGroupIDs, err := n.getSecurityGroupIDs(ctx, resource.Spec.ENI)
	if err != nil {
		return 0,
			errUnableToGetSecurityGroups,
			fmt.Errorf("%s %s", errUnableToGetSecurityGroups, err)
	}

	desc := "Cilium-CNI (" + n.node.InstanceID() + ")"

	// Must allocate secondary ENI IPs as needed, up to ENI instance limit - 1 (reserve 1 for primary IP)
	toAllocate := math.IntMin(allocation.MaxIPsToAllocate, limits.IPv4-1)
	// Validate whether request has already been fulfilled in the meantime
	if toAllocate == 0 {
		return 0, "", nil
	}

	index := n.findNextIndex(int32(*resource.Spec.ENI.FirstInterfaceIndex))

	scopedLog = scopedLog.WithFields(logrus.Fields{
		"securityGroupIDs": securityGroupIDs,
		"subnetID":         bestSubnet.ID,
		"addresses":        toAllocate,
	})
	scopedLog.Info("No more IPs available, creating new ENI")

	eniID, eni, err := n.manager.api.CreateNetworkInterface(ctx, int32(toAllocate), bestSubnet.ID, desc, securityGroupIDs)
	if err != nil {
		return 0, errUnableToCreateENI, fmt.Errorf("%s %s", errUnableToCreateENI, err)
	}

	scopedLog = scopedLog.WithField(fieldEniID, eniID)
	scopedLog.Info("Created new ENI")

	var attachmentID string
	for attachRetries := 0; attachRetries < maxAttachRetries; attachRetries++ {
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
			scopedLog.WithError(delErr).Warning("Unable to undo ENI creation after failure to attach")
		}

		if n.errorInstanceNotRunning(err) {
			return toAllocate, "", nil
		}

		return 0,
			errUnableToAttachENI,
			fmt.Errorf("%s at index %d: %s", errUnableToAttachENI, index, err)
	}

	scopedLog = scopedLog.WithFields(logrus.Fields{
		"attachmentID": attachmentID,
		"index":        index,
	})

	eni.Number = int(index)

	scopedLog.Info("Attached ENI to instance")

	if resource.Spec.ENI.DeleteOnTermination == nil || *resource.Spec.ENI.DeleteOnTermination {
		// We have an attachment ID from the last API, which lets us mark the
		// interface as delete on termination
		err = n.manager.api.ModifyNetworkInterface(ctx, eniID, attachmentID, true)
		if err != nil {
			delErr := n.manager.api.DeleteNetworkInterface(ctx, eniID)
			if delErr != nil {
				scopedLog.WithError(delErr).Warning("Unable to undo ENI creation after failure to attach")
			}

			if n.errorInstanceNotRunning(err) {
				return toAllocate, "", nil
			}

			return 0, errUnableToMarkENIForDeletion, fmt.Errorf("unable to mark ENI for deletion on termination: %s", err)
		}
	}

	// Add the information of the created ENI to the instances manager
	n.manager.UpdateENI(n.node.InstanceID(), eni)
	return toAllocate, "", nil
}

// ResyncInterfacesAndIPs is called to retrieve and ENIs and IPs as known to
// the EC2 API and return them
func (n *Node) ResyncInterfacesAndIPs(ctx context.Context, scopedLog *logrus.Entry) (ipamTypes.AllocationMap, error) {
	// n.node does not need to be protected by n.mutex as it is only written to
	// upon creation of `n`
	instanceID := n.node.InstanceID()
	available := ipamTypes.AllocationMap{}

	n.mutex.Lock()
	n.enis = map[string]eniTypes.ENI{}

	n.manager.ForeachInstance(instanceID,
		func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			if !ok {
				return nil
			}

			n.enis[e.ID] = *e
			index := *n.k8sObj.Spec.ENI.FirstInterfaceIndex

			if e.Number < index {
				return nil
			}

			for _, ip := range e.Addresses {
				available[ip] = ipamTypes.AllocationIP{Resource: e.ID}
			}
			return nil
		})
	enis := len(n.enis)
	n.mutex.Unlock()

	// An ec2 instance has at least one ENI attached, no ENI found implies instance not found.
	if enis == 0 {
		scopedLog.Warning("Instance not found! Please delete corresponding ciliumnode if instance has already been deleted.")
		return nil, fmt.Errorf("unable to retrieve ENIs")
	}

	return available, nil
}

// GetMaximumAllocatableIPv4 returns the maximum amount of IPv4 addresses
// that can be allocated to the instance
func (n *Node) GetMaximumAllocatableIPv4() int {
	if n == nil {
		log.Warningf("Could not determine first interface index, %s", getMaximumAllocatableIPv4FailureWarningStr)
		return 0
	}

	n.mutex.RLock()
	defer n.mutex.RUnlock()

	// Retrieve FirstInterfaceIndex from node spec
	if n.k8sObj == nil ||
		n.k8sObj.Spec.ENI.FirstInterfaceIndex == nil {
		n.loggerLocked().WithFields(logrus.Fields{
			"first-interface-index": "unknown",
		}).Warningf("Could not determine first interface index, %s", getMaximumAllocatableIPv4FailureWarningStr)
		return 0
	}
	firstInterfaceIndex := *n.k8sObj.Spec.ENI.FirstInterfaceIndex

	// Retrieve limits for the instance type
	limits, limitsAvailable := n.getLimitsLocked()
	if !limitsAvailable {
		n.loggerLocked().WithFields(logrus.Fields{
			"adaptors-limit":        "unknown",
			"first-interface-index": firstInterfaceIndex,
		}).Warningf("Could not determined instance limits, %s", getMaximumAllocatableIPv4FailureWarningStr)
		return 0
	}

	// Validate the amount of adapters is bigger than the configured FirstInterfaceIndex
	if limits.Adapters < firstInterfaceIndex {
		n.loggerLocked().WithFields(logrus.Fields{
			"adaptors-limit":        limits.Adapters,
			"first-interface-index": firstInterfaceIndex,
		}).Warningf(
			"Instance type network adapters limit is lower than the configured FirstInterfaceIndex, %s",
			getMaximumAllocatableIPv4FailureWarningStr,
		)
		return 0
	}

	// Return the maximum amount of IP addresses allocatable on the instance
	return (limits.Adapters - firstInterfaceIndex) * limits.IPv4
}

var adviseOperatorFlagOnce sync.Once

// GetMinimumAllocatableIPv4 returns the minimum amount of IPv4 addresses that
// must be allocated to the instance.
func (n *Node) GetMinimumAllocatableIPv4() int {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	minimum := defaults.IPAMPreAllocation

	if n.k8sObj == nil || n.k8sObj.Spec.ENI.FirstInterfaceIndex == nil {
		n.loggerLocked().WithFields(logrus.Fields{
			"adaptors-limit": "unknown",
			"pre-allocate":   minimum,
		}).Warning("Could not determine first-interface-index, falling back to default pre-allocate value")
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
			n.loggerLocked().WithFields(logrus.Fields{
				"instance-type": n.k8sObj.Spec.ENI.InstanceType,
			}).Warningf(
				"Unable to find limits for instance type, consider setting --%s=true on the Operator",
				option.UpdateEC2AdapterLimitViaAPI,
			)
		})

		n.loggerLocked().WithFields(logrus.Fields{
			"adaptors-limit":        "unknown",
			"first-interface-index": index,
			"pre-allocate":          minimum,
		}).Warning("Could not determine instance limits, falling back to default pre-allocate value")
		return minimum
	}

	// We cannot allocate any IPs if this is the case because all the ENIs will
	// be skipped.
	if index >= limits.Adapters {
		return 0
	}

	return math.IntMin(minimum, (limits.Adapters-index)*limits.IPv4)
}
