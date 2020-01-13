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
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/math"

	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/sirupsen/logrus"
)

const (
	// maxAttachRetries is the maximum number of attachment retries
	maxAttachRetries = 5
)

// Node represents an AWS EC2 instance capable of allocating ENIs
type Node struct {
	mutex lock.RWMutex

	// node contains the general purpose fields of a node
	node *ipam.Node

	// enis is the list of ENIs attached to the node indexed by ENI ID.
	// Protected by Node.mutex.
	enis map[string]v2.ENI

	// k8sObj is the CiliumNode custom resource representing the node
	k8sObj *v2.CiliumNode

	// manager is the EC2 node manager responsible for this node
	manager *InstancesManager
}

// UpdatedNode is called when an update to the CiliumNode is received.
func (n *Node) UpdatedNode(obj *v2.CiliumNode) {
	n.k8sObj = obj
}

func (n *Node) GetMaxAboveWatermark() int {
	if n.k8sObj.Spec.IPAM.MaxAboveWatermark != 0 {
		return n.k8sObj.Spec.IPAM.MaxAboveWatermark
	}
	return n.k8sObj.Spec.ENI.MaxAboveWatermark
}

func (n *Node) GetPreAllocate() int {
	if n.k8sObj.Spec.IPAM.PreAllocate != 0 {
		return n.k8sObj.Spec.IPAM.PreAllocate
	}
	if n.k8sObj.Spec.ENI.PreAllocate != 0 {
		return n.k8sObj.Spec.ENI.PreAllocate
	}
	return defaults.ENIPreAllocation
}

func (n *Node) GetMinAllocate() int {
	if n.k8sObj.Spec.IPAM.MinAllocate != 0 {
		return n.k8sObj.Spec.IPAM.MinAllocate
	}
	return n.k8sObj.Spec.ENI.MinAllocate
}

// PopulateStatusFields fills in the status field of the CiliumNode custom
// resource with ENI specific information
func (n *Node) PopulateStatusFields(k8sObj *v2.CiliumNode) {
	k8sObj.Status.ENI.ENIs = n.getENIs()
}

// PopulateSpecFields fills in the spec field of the CiliumNode custom resource
// with ENI specific information
func (n *Node) PopulateSpecFields(k8sObj *v2.CiliumNode) {
	if k8sObj.Spec.ENI.PreAllocate == 0 {
		k8sObj.Spec.ENI.PreAllocate = defaults.ENIPreAllocation
	}
}

// getLimits returns the interface and IP limits of this node
func (n *Node) getLimits() (ipam.Limits, bool) {
	return getLimits(n.k8sObj.Spec.ENI.InstanceType)
}

// PrepareIPRelease prepares the release of ENI IPs.
func (n *Node) PrepareIPRelease(excessIPs int, scopedLog *logrus.Entry) *ipam.ReleaseAction {
	r := &ipam.ReleaseAction{}

	// Iterate over ENIs on this node, select the ENI with the most
	// addresses available for release
	for key, e := range n.enis {
		scopedLog.WithFields(logrus.Fields{
			fieldEniID:     e.ID,
			"needIndex":    n.k8sObj.Spec.ENI.FirstInterfaceIndex,
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

		firstEniWithFreeIpFound := r.IPsToRelease == nil
		eniWithMoreFreeIpsFound := maxReleaseOnENI > len(r.IPsToRelease)
		// Select the ENI with the most addresses available for release
		if firstEniWithFreeIpFound || eniWithMoreFreeIpsFound {
			r.InterfaceID = key
			r.PoolID = ipam.PoolID(e.Subnet.ID)
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

	for key, e := range n.enis {
		scopedLog.WithFields(logrus.Fields{
			fieldEniID:     e.ID,
			"needIndex":    n.k8sObj.Spec.ENI.FirstInterfaceIndex,
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
				a.PoolID = ipam.PoolID(subnet.ID)
				a.AvailableForAllocation = math.IntMin(subnet.AvailableAddresses, availableOnENI)
			}
		}
	}

	a.AvailableInterfaces = limits.Adapters - len(n.enis) + a.AvailableInterfaces

	return
}

// AllocateIPs performs the ENI allocation oepration
func (n *Node) AllocateIPs(ctx context.Context, a *ipam.AllocationAction) error {
	return n.manager.api.AssignPrivateIpAddresses(ctx, a.InterfaceID, int64(a.AvailableForAllocation))
}

// getENIs returns a copy of all ENIs attached to the node
func (n *Node) getENIs() (enis map[string]v2.ENI) {
	enis = map[string]v2.ENI{}
	n.mutex.RLock()
	for _, e := range n.enis {
		enis[e.ID] = e
	}
	n.mutex.RUnlock()
	return
}

func (n *Node) getSecurityGroupIDs(ctx context.Context) ([]string, error) {
	// 1. check explicit security groups associations via checking Spec.ENI.SecurityGroups
	// 2. check if Spec.ENI.SecurityGroupTags is passed and if so filter by those
	// 3. if 1 and 2 give no results derive the security groups from eth0

	eniSpec := n.k8sObj.Spec.ENI
	if len(eniSpec.SecurityGroups) > 0 {
		return eniSpec.SecurityGroups, nil
	}

	if len(eniSpec.SecurityGroupTags) > 0 {
		securityGroups := n.manager.FindSecurityGroupByTags(eniSpec.VpcID, eniSpec.SecurityGroupTags)
		if len(securityGroups) == 0 {
			log.WithFields(logrus.Fields{
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

	if eni := n.manager.GetENI(n.k8sObj.Spec.ENI.InstanceID, 0); eni != nil {
		return eni.SecurityGroups, nil
	}

	return nil, fmt.Errorf("failed to get security group ids")
}

func (n *Node) errorInstanceNotRunning(err error) (notRunning bool) {
	// This is handling the special case when an instance has been
	// terminated but the grace period has delayed the Kubernetes node
	// deletion event to not have been sent out yet. The next ENI resync
	// will cause the instance to be marked as inactive.
	if strings.Contains(err.Error(), "is not 'running'") {
		n.node.SetRunningLocked(false)
		log.Info("Marking node as not running")
	}
	return
}

func isAttachmentIndexConflict(err error) bool {
	e, ok := err.(awserr.Error)
	return ok && e.Code() == "InvalidParameterValue" && strings.Contains(e.Message(), "interface attached at device")
}

// indexExists returns true if the specified index is occupied by an ENI in the
// slice of ENIs
func indexExists(enis map[string]v2.ENI, index int64) bool {
	for _, e := range enis {
		if e.Number == int(index) {
			return true
		}
	}
	return false
}

// findNextIndex returns the next available index with the provided index being
// the first candidate
func (n *Node) findNextIndex(index int64) int64 {
	for indexExists(n.enis, index) {
		index++
	}
	return index
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

	bestSubnet := n.manager.FindSubnetByTags(n.k8sObj.Spec.ENI.VpcID, n.k8sObj.Spec.ENI.AvailabilityZone, n.k8sObj.Spec.ENI.SubnetTags)
	if bestSubnet == nil {
		return 0, errUnableToFindSubnet, fmt.Errorf("No matching subnet available for interface creation (VPC=%s AZ=%s SubnetTags=%s",
			n.k8sObj.Spec.ENI.VpcID, n.k8sObj.Spec.ENI.AvailabilityZone, n.k8sObj.Spec.ENI.SubnetTags)
	}

	securityGroupIDs, err := n.getSecurityGroupIDs(ctx)
	if err != nil {
		return 0, errUnableToGetSecurityGroups, fmt.Errorf("%s %s", errUnableToGetSecurityGroups, err)
	}

	desc := "Cilium-CNI (" + n.k8sObj.Spec.ENI.InstanceID + ")"
	// Must allocate secondary ENI IPs as needed, up to ENI instance limit - 1 (reserve 1 for primary IP)
	toAllocate := math.IntMin(allocation.MaxIPsToAllocate, limits.IPv4-1)
	// Validate whether request has already been fulfilled in the meantime
	if toAllocate == 0 {
		return 0, "", nil
	}

	index := n.findNextIndex(int64(*n.k8sObj.Spec.ENI.FirstInterfaceIndex))

	scopedLog = scopedLog.WithFields(logrus.Fields{
		"securityGroupIDs": securityGroupIDs,
		"subnetID":         bestSubnet.ID,
		"addresses":        toAllocate,
	})
	scopedLog.Info("No more IPs available, creating new ENI")

	eniID, eni, err := n.manager.api.CreateNetworkInterface(ctx, int64(toAllocate), bestSubnet.ID, desc, securityGroupIDs)
	if err != nil {
		return 0, errUnableToCreateENI, fmt.Errorf("%s %s", errUnableToCreateENI, err)
	}

	scopedLog = scopedLog.WithField(fieldEniID, eniID)
	scopedLog.Info("Created new ENI")

	var attachmentID string
	for attachRetries := 0; attachRetries < maxAttachRetries; attachRetries++ {
		attachmentID, err = n.manager.api.AttachNetworkInterface(ctx, index, n.k8sObj.Spec.ENI.InstanceID, eniID)

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

		return 0, errUnableToAttachENI, fmt.Errorf("%s at index %d: %s", errUnableToAttachENI, index, err)
	}

	scopedLog = scopedLog.WithFields(logrus.Fields{
		"attachmentID": attachmentID,
		"index":        index,
	})

	eni.Number = int(index)

	if n.k8sObj.Spec.ENI.DeleteOnTermination == nil || *n.k8sObj.Spec.ENI.DeleteOnTermination {
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

			return 0, errUnableToMarkENIForDeletion, fmt.Errorf("%s %s", errUnableToMarkENIForDeletion, err)
		}
	}

	if len(n.manager.eniTags) != 0 {
		if err := n.manager.api.TagENI(ctx, eniID, n.manager.eniTags); err != nil {
			// treating above as a warn rather than error since it's not mandatory for ENI tagging to succeed
			// given at this point given that it won't affect IPAM functionality
			scopedLog.WithError(err).Warning("Unable to tag ENI")
		}
	}

	// Add the information of the created ENI to the instances manager
	n.manager.UpdateENI(n.k8sObj.Spec.ENI.InstanceID, eni)
	return toAllocate, "", nil
}

// LogFields extends the log entry with ENI specific fields
func (n *Node) LogFields(logger *logrus.Entry) *logrus.Entry {
	if n.k8sObj != nil {
		logger = logger.WithField("instanceID", n.k8sObj.Spec.ENI.InstanceID)
	}
	return logger
}

// ResyncInterfacesAndIPs is called to retrieve and ENIs and IPs as known to
// the EC2 API and return them
func (n *Node) ResyncInterfacesAndIPs(ctx context.Context, scopedLog *logrus.Entry) (map[string]v2.AllocationIP, error) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	available := map[string]v2.AllocationIP{}
	n.enis = map[string]v2.ENI{}
	enis := n.manager.GetENIs(n.k8sObj.Spec.ENI.InstanceID)
	// An ec2 instance has at least one ENI attached, no ENI found implies instance not found.
	if len(enis) == 0 {
		scopedLog.Warning("Instance not found! Please delete corresponding ciliumnode if instance has already been deleted.")
		return nil, fmt.Errorf("unable to retrieve ENIs")
	}

	for _, e := range enis {
		n.enis[e.ID] = *e

		if e.Number < *n.k8sObj.Spec.ENI.FirstInterfaceIndex {
			continue
		}

		for _, ip := range e.Addresses {
			available[ip] = v2.AllocationIP{Resource: e.ID}
		}
	}

	return available, nil
}
