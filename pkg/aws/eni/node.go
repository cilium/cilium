// Copyright 2019 Authors of Cilium
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
	"time"

	"github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/math"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"

	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/sirupsen/logrus"
)

const (
	// warningInterval is the interval for warnings which should be done
	// once and then repeated if the warning persists.
	warningInterval = time.Hour

	// maxAttachRetries is the maximum number of attachment retries
	maxAttachRetries = 5
)

// Node represents a Kubernetes node running Cilium with an associated
// CiliumNode custom resource
type Node struct {
	// mutex protects all members of this structure
	mutex lock.RWMutex

	// name is the name of the node
	name string

	// resource is the link to the CiliumNode custom resource
	resource *v2.CiliumNode

	// stats provides accounting for various per node statistics
	stats nodeStatistics

	// lastMaxAdapterWarning is the timestamp when the last warning was
	// printed that this node is out of adapters
	lastMaxAdapterWarning time.Time

	// instanceNotRunning is true when the EC2 instance backing the node is
	// not running. This state is detected based on error messages returned
	// when modifying instance state
	instanceNotRunning bool

	// waitingForPoolMaintenance is true when the node is subject to an
	// IP allocation or release which must be performed before another
	// allocation or release can be attempted
	waitingForPoolMaintenance bool

	// resyncNeeded is set to the current time when a resync with the EC2
	// API is required. The timestamp is required to ensure that this is
	// only reset if the resync started after the time stored in
	// resyncNeeded. This is needed because resyncs and allocations happen
	// in parallel.
	resyncNeeded time.Time

	enis map[string]v2.ENI

	available map[string]v2.AllocationIP

	manager *NodeManager

	// poolMaintainer is the trigger used to assign/unassign
	// private IP addresses of this node.
	// It ensures that multiple requests to operate private IPs are
	// batched together if pool maintenance is still ongoing.
	poolMaintainer *trigger.Trigger

	// k8sSync is the trigger used to synchronize node information with the
	// K8s apiserver. The trigger is used to batch multiple updates
	// together if the apiserver is slow to respond or subject to rate
	// limiting.
	k8sSync *trigger.Trigger
}

type nodeStatistics struct {
	// usedIPs is the number of IPs currently in use
	usedIPs int

	// availableIPs is the number of IPs currently available for allocation
	// by the node
	availableIPs int

	// neededIPs is the number of IPs needed to reach the PreAllocate
	// watermwark
	neededIPs int

	// excessIPs is the number of free IPs exceeding MaxAboveWatermark
	excessIPs int

	// remainingInterfaces is the number of ENIs that can either be
	// allocated or have not yet exhausted the ENI specific quota of
	// addresses
	remainingInterfaces int
}

func (n *Node) logger() *logrus.Entry {
	if n == nil {
		return log
	}

	n.mutex.RLock()
	defer n.mutex.RUnlock()

	return n.loggerLocked()
}

func (n *Node) loggerLocked() *logrus.Entry {
	if n == nil {
		return log
	}

	logger := log.WithField(fieldName, n.name)

	if n.resource != nil {
		logger = logger.WithField("instanceID", n.resource.Spec.ENI.InstanceID)
	}

	return logger
}

func (n *Node) getNeededAddresses() int {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if n.stats.neededIPs > 0 {
		return n.stats.neededIPs
	}
	if option.Config.AwsReleaseExcessIps && n.stats.excessIPs > 0 {
		// Nodes are sorted by needed addresses, return negative values of excessIPs
		// so that nodes with IP deficit are resolved first
		return n.stats.excessIPs * -1
	}
	return 0
}

func calculateNeededIPs(availableIPs, usedIPs, preAllocate, minAllocate int) (neededIPs int) {
	if preAllocate == 0 {
		preAllocate = defaults.ENIPreAllocation
	}

	neededIPs = preAllocate - (availableIPs - usedIPs)
	if neededIPs < 0 {
		neededIPs = 0
	}

	if minAllocate > 0 {
		neededIPs = math.IntMax(neededIPs, minAllocate-availableIPs)
	}

	return
}

func calculateExcessIPs(availableIPs, usedIPs, preAllocate, minAllocate, maxAboveWatermark int) (excessIPs int) {
	if preAllocate == 0 {
		preAllocate = defaults.ENIPreAllocation
	}

	// keep availableIPs above minAllocate + maxAboveWatermark as long as
	// the initial socket of min-allocate + max-above-watermark has not
	// been used up yet. This is the maximum potential allocation that will
	// happen on initial bootstrap.  Depending on interface restrictions,
	// the actual allocation may be below this but we always want to avoid
	// releasing IPs that have just been allocated.
	if usedIPs <= (minAllocate + maxAboveWatermark) {
		if availableIPs <= (minAllocate + maxAboveWatermark) {
			return 0
		}
	}

	// Once above the minimum allocation level, calculate based on
	// pre-allocation limit with the max-above-watermark limit calculated
	// in. This is again a best-effort calculation, depending on the
	// interface restrictions, less than max-above-watermark may have been
	// allocated but we never want to release IPs that have been allocated
	// because of max-above-watermark.
	excessIPs = availableIPs - usedIPs - preAllocate - maxAboveWatermark
	if excessIPs < 0 {
		excessIPs = 0
	}

	return
}

func (n *Node) updatedResource(resource *v2.CiliumNode) bool {
	// Deep copy the resource before storing it. This way we are
	// not dependent on caller not using the resource after this
	// call.
	resource = resource.DeepCopy()

	n.mutex.Lock()
	// Any modification to the custom resource is seen as a sign that the
	// instance is alive
	if n.instanceNotRunning {
		n.loggerLocked().Info("Marking node as running")
		n.instanceNotRunning = false
	}
	n.resource = resource
	n.recalculateLocked()
	allocationNeeded := n.allocationNeeded()
	if allocationNeeded {
		n.waitingForPoolMaintenance = true
		n.poolMaintainer.Trigger()
	}
	n.mutex.Unlock()

	return allocationNeeded
}

func (n *Node) recalculateLocked() {
	n.enis = map[string]v2.ENI{}
	n.available = map[string]v2.AllocationIP{}
	enis := n.manager.instancesAPI.GetENIs(n.resource.Spec.ENI.InstanceID)
	// An ec2 instance has at least one ENI attached, no ENI found implies instance not found.
	if len(enis) == 0 {
		n.loggerLocked().Warning("Instance not found! Please delete corresponding ciliumnode if instance has already been deleted.")
		// Avoid any further action
		n.stats.neededIPs = 0
		n.stats.excessIPs = 0
		return
	}
	for _, e := range enis {
		n.enis[e.ID] = *e

		if e.Number < *n.resource.Spec.ENI.FirstInterfaceIndex {
			continue
		}

		for _, ip := range e.Addresses {
			n.available[ip] = v2.AllocationIP{Resource: e.ID}
		}
	}
	n.stats.usedIPs = len(n.resource.Status.IPAM.Used)
	n.stats.availableIPs = len(n.available)
	n.stats.neededIPs = calculateNeededIPs(n.stats.availableIPs, n.stats.usedIPs, n.resource.Spec.ENI.PreAllocate, n.resource.Spec.ENI.MinAllocate)
	n.stats.excessIPs = calculateExcessIPs(n.stats.availableIPs, n.stats.usedIPs, n.resource.Spec.ENI.PreAllocate, n.resource.Spec.ENI.MinAllocate, n.resource.Spec.ENI.MaxAboveWatermark)

	n.loggerLocked().WithFields(logrus.Fields{
		"available":                 n.stats.availableIPs,
		"used":                      n.stats.usedIPs,
		"toAlloc":                   n.stats.neededIPs,
		"toRelease":                 n.stats.excessIPs,
		"waitingForPoolMaintenance": n.waitingForPoolMaintenance,
		"resyncNeeded":              n.resyncNeeded,
	}).Debug("Recalculated needed addresses")
}

// allocationNeeded returns true if this node requires IPs to be allocated
func (n *Node) allocationNeeded() bool {
	return !n.waitingForPoolMaintenance && n.resyncNeeded.IsZero() && n.stats.neededIPs > 0
}

// releaseNeeded returns true if this node requires IPs to be released
func (n *Node) releaseNeeded() bool {
	return option.Config.AwsReleaseExcessIps && !n.waitingForPoolMaintenance && n.resyncNeeded.IsZero() && n.stats.excessIPs > 0
}

// ENIs returns a copy of all ENIs attached to the node
func (n *Node) ENIs() (enis map[string]v2.ENI) {
	enis = map[string]v2.ENI{}
	n.mutex.RLock()
	for _, e := range n.enis {
		enis[e.ID] = e
	}
	n.mutex.RUnlock()
	return
}

// Pool returns the IP allocation pool available to the node
func (n *Node) Pool() (pool map[string]v2.AllocationIP) {
	pool = map[string]v2.AllocationIP{}
	n.mutex.RLock()
	for k, allocationIP := range n.available {
		pool[k] = allocationIP
	}
	n.mutex.RUnlock()
	return
}

// ResourceCopy returns a deep copy of the CiliumNode custom resource
// associated with the node
func (n *Node) ResourceCopy() *v2.CiliumNode {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	return n.resource.DeepCopy()
}

func (n *Node) getSecurityGroupIDs(ctx context.Context) ([]string, error) {
	// 1. check explicit security groups associations via checking Spec.ENI.SecurityGroups
	// 2. check if Spec.ENI.SecurityGroupTags is passed and if so filter by those
	// 3. if 1 and 2 give no results derive the security groups from eth0

	eniSpec := n.resource.Spec.ENI
	if len(eniSpec.SecurityGroups) > 0 {
		return eniSpec.SecurityGroups, nil
	}

	if len(eniSpec.SecurityGroupTags) > 0 {
		securityGroups := n.manager.instancesAPI.FindSecurityGroupByTags(eniSpec.VpcID, eniSpec.SecurityGroupTags)
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

	if eni := n.manager.instancesAPI.GetENI(n.resource.Spec.ENI.InstanceID, 0); eni != nil {
		return eni.SecurityGroups, nil
	}

	return nil, fmt.Errorf("failed to get security group ids")
}

func (n *Node) errorInstanceNotRunning(err error) (notRunning bool) {
	// This is handling the special case when an instance has been
	// terminated but the grace period has delayed the Kubernetes node
	// deletion event to not have been sent out yet. The next ENI resync
	// will cause the instance to be marked as inactive.
	notRunning = strings.Contains(err.Error(), "is not 'running'")
	if notRunning {
		n.mutex.Lock()
		n.instanceNotRunning = true
		n.loggerLocked().Info("Marking node as not running")
		n.mutex.Unlock()
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

// allocateENI creates an additional ENI and attaches it to the instance as
// specified by the ciliumNode. neededAddresses of secondary IPs are assigned
// to the interface up to the maximum number of addresses as allowed by the
// ENI.
func (n *Node) allocateENI(ctx context.Context, s *types.Subnet, a *allocatableResources) error {
	nodeResource := n.ResourceCopy()
	n.mutex.RLock()

	securityGroupIDs, err := n.getSecurityGroupIDs(ctx)
	if err != nil {
		n.mutex.RUnlock()
		return fmt.Errorf("failed to get security groups for node %s: %s", n.name, err.Error())
	}

	neededAddresses := n.stats.neededIPs
	desc := "Cilium-CNI (" + n.resource.Spec.ENI.InstanceID + ")"
	// Must allocate secondary ENI IPs as needed, up to ENI instance limit - 1 (reserve 1 for primary IP)
	toAllocate := int64(math.IntMin(neededAddresses+nodeResource.Spec.ENI.MaxAboveWatermark, a.limits.IPv4-1))
	// Validate whether request has already been fulfilled in the meantime
	if toAllocate == 0 {
		n.mutex.RUnlock()
		return nil
	}

	index := n.findNextIndex(int64(*nodeResource.Spec.ENI.FirstInterfaceIndex))

	scopedLog := n.loggerLocked().WithFields(logrus.Fields{
		"securityGroupIDs": securityGroupIDs,
		"subnetID":         s.ID,
		"addresses":        toAllocate,
	})
	scopedLog.Info("No more IPs available, creating new ENI")
	n.mutex.RUnlock()

	eniID, eni, err := n.manager.ec2API.CreateNetworkInterface(ctx, toAllocate, s.ID, desc, securityGroupIDs)
	if err != nil {
		n.manager.metricsAPI.IncENIAllocationAttempt("ENI creation failed", s.ID)
		return fmt.Errorf("unable to create ENI: %s", err)
	}

	scopedLog = scopedLog.WithField(fieldEniID, eniID)
	scopedLog.Info("Created new ENI")

	var attachmentID string
	for attachRetries := 0; attachRetries < maxAttachRetries; attachRetries++ {
		attachmentID, err = n.manager.ec2API.AttachNetworkInterface(ctx, index, nodeResource.Spec.ENI.InstanceID, eniID)

		// The index is already in use, this can happen if the local
		// list of ENIs is oudated.  Retry the attachment to avoid
		// having to delete the ENI
		if !isAttachmentIndexConflict(err) {
			break
		}

		index = n.findNextIndex(index + 1)
	}

	if err != nil {
		delErr := n.manager.ec2API.DeleteNetworkInterface(ctx, eniID)
		if delErr != nil {
			scopedLog.WithError(delErr).Warning("Unable to undo ENI creation after failure to attach")
		}

		if n.errorInstanceNotRunning(err) {
			return nil
		}

		n.manager.metricsAPI.IncENIAllocationAttempt("ENI attachment failed", s.ID)

		return fmt.Errorf("unable to attach ENI at index %d: %s", index, err)
	}

	scopedLog = scopedLog.WithFields(logrus.Fields{
		"attachmentID": attachmentID,
		"index":        index,
	})

	eni.Number = int(index)

	scopedLog.Info("Attached ENI to instance")

	if nodeResource.Spec.ENI.DeleteOnTermination == nil || *nodeResource.Spec.ENI.DeleteOnTermination {
		// We have an attachment ID from the last API, which lets us mark the
		// interface as delete on termination
		err = n.manager.ec2API.ModifyNetworkInterface(ctx, eniID, attachmentID, true)
		if err != nil {
			delErr := n.manager.ec2API.DeleteNetworkInterface(ctx, eniID)
			if delErr != nil {
				scopedLog.WithError(delErr).Warning("Unable to undo ENI creation after failure to attach")
			}

			if n.errorInstanceNotRunning(err) {
				return nil
			}

			n.manager.metricsAPI.IncENIAllocationAttempt("ENI modification failed", s.ID)
			return fmt.Errorf("unable to mark ENI for deletion on termination: %s", err)
		}
	}

	if len(n.manager.eniTags) != 0 {
		if err := n.manager.ec2API.TagENI(ctx, eniID, n.manager.eniTags); err != nil {
			// treating above as a warn rather than error since it's not mandatory for ENI tagging to succeed
			// given at this point given that it won't affect IPAM functionality
			scopedLog.WithError(err).Warning("Unable to tag ENI")
		}
	}

	// Add the information of the created ENI to the instances manager
	n.manager.instancesAPI.UpdateENI(n.resource.Spec.ENI.InstanceID, eni)

	n.manager.metricsAPI.IncENIAllocationAttempt("success", s.ID)
	n.manager.metricsAPI.AddIPAllocation(s.ID, toAllocate)

	return nil
}

// allocatableResources represents the resources available for allocation for a
// particular ciliumNode. If an existing ENI has IP allocation capacity left,
// that capacity is used up first. If not, an available index is found to
// create a new ENI.
type allocatableResources struct {
	instanceID          string
	eni                 string
	subnet              *types.Subnet
	availableOnSubnet   int
	limits              ipam.Limits
	remainingInterfaces int
	totalENIs           int
	ipsToReleaseOnENI   []string
}

func (n *Node) determineMaintenanceAction() (*allocatableResources, error) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	instanceType := n.resource.Spec.ENI.InstanceType
	limits, ok := GetLimits(instanceType)

	scopedLog := n.loggerLocked()

	if !ok {
		n.manager.metricsAPI.IncENIAllocationAttempt("limits unavailable", "")
		return nil, fmt.Errorf("Unable to determine limits of instance type '%s'", instanceType)
	}

	a := &allocatableResources{
		instanceID: n.resource.Spec.ENI.InstanceID,
		limits:     limits,
		totalENIs:  len(n.enis),
	}

	// Validate that the node still requires addresses to be released, the
	// request may have been resolved in the meantime.
	if option.Config.AwsReleaseExcessIps && n.stats.excessIPs > 0 {
		// Iterate over ENIs on this node, select the ENI with the most
		// addresses available for release
		for key, e := range n.enis {
			scopedLog.WithFields(logrus.Fields{
				fieldEniID:     e.ID,
				"needIndex":    n.resource.Spec.ENI.FirstInterfaceIndex,
				"index":        e.Number,
				"addressLimit": a.limits.IPv4,
				"numAddresses": len(e.Addresses),
			}).Debug("Considering ENI for IP release")

			if e.Number < *n.resource.Spec.ENI.FirstInterfaceIndex {
				continue
			}

			// Count free IP addresses on this ENI
			ipsOnENI := n.resource.Status.ENI.ENIs[e.ID].Addresses
			freeIpsOnENI := []string{}
			for _, ip := range ipsOnENI {
				_, ipUsed := n.resource.Status.IPAM.Used[ip]
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
				"excessIPs":      n.stats.excessIPs,
				"freeOnENICount": freeOnENICount,
			}).Debug("ENI has unused IPs that can be released")
			maxReleaseOnENI := math.IntMin(freeOnENICount, n.stats.excessIPs)

			firstEniWithFreeIpFound := a.ipsToReleaseOnENI == nil
			eniWithMoreFreeIpsFound := maxReleaseOnENI > len(a.ipsToReleaseOnENI)
			// Select the ENI with the most addresses available for release
			if firstEniWithFreeIpFound || eniWithMoreFreeIpsFound {
				a.eni = key
				a.subnet = &types.Subnet{ID: e.Subnet.ID}
				a.ipsToReleaseOnENI = freeIpsOnENI[:maxReleaseOnENI]
			}
		}

		if a.ipsToReleaseOnENI != nil {
			scopedLog = scopedLog.WithFields(logrus.Fields{
				"available":      n.stats.availableIPs,
				"used":           n.stats.usedIPs,
				"excess":         n.stats.excessIPs,
				"releasing":      a.ipsToReleaseOnENI,
				"selectedENI":    n.enis[a.eni],
				"selectedSubnet": a.subnet.ID,
			})
			scopedLog.Info("Releasing excess IPs from node")
		}
		return a, nil
	}

	// Validate that the node still requires addresses to be allocated, the
	// request may have been resolved in the meantime.
	maxAllocate := n.stats.neededIPs + n.resource.Spec.ENI.MaxAboveWatermark
	if n.stats.neededIPs == 0 {
		return nil, nil
	}

	for key, e := range n.enis {
		scopedLog.WithFields(logrus.Fields{
			fieldEniID:     e.ID,
			"needIndex":    n.resource.Spec.ENI.FirstInterfaceIndex,
			"index":        e.Number,
			"addressLimit": a.limits.IPv4,
			"numAddresses": len(e.Addresses),
		}).Debug("Considering ENI for allocation")

		if e.Number < *n.resource.Spec.ENI.FirstInterfaceIndex {
			continue
		}

		availableOnENI := math.IntMax(limits.IPv4-len(e.Addresses), 0)
		if availableOnENI <= 0 {
			continue
		} else {
			a.remainingInterfaces++
		}

		scopedLog.WithFields(logrus.Fields{
			fieldEniID:       e.ID,
			"maxAllocate":    maxAllocate,
			"availableOnEni": availableOnENI,
		}).Debug("ENI has IPs available")
		maxAllocateOnENI := math.IntMin(availableOnENI, maxAllocate)

		if subnet := n.manager.instancesAPI.GetSubnet(e.Subnet.ID); subnet != nil {
			if subnet.AvailableAddresses > 0 && a.eni == "" {
				scopedLog.WithFields(logrus.Fields{
					"subnetID":           e.Subnet.ID,
					"availableAddresses": subnet.AvailableAddresses,
				}).Debug("Subnet has IPs available")
				a.eni = key
				a.subnet = subnet
				a.availableOnSubnet = math.IntMin(subnet.AvailableAddresses, maxAllocateOnENI)
			}
		}
	}

	a.remainingInterfaces = limits.Adapters - a.totalENIs + a.remainingInterfaces
	n.stats.remainingInterfaces = a.remainingInterfaces

	scopedLog = scopedLog.WithFields(logrus.Fields{
		"available":           n.stats.availableIPs,
		"used":                n.stats.usedIPs,
		"toAlloc":             n.stats.neededIPs,
		"remainingInterfaces": n.stats.remainingInterfaces,
	})

	if a.eni != "" {
		scopedLog = scopedLog.WithFields(logrus.Fields{
			"selectedENI":          n.enis[a.eni],
			"selectedSubnet":       a.subnet.ID,
			"availableIPsOnSubnet": a.subnet.AvailableAddresses,
		})
	}

	scopedLog.Info("Resolving IP deficit of node")

	return a, nil
}

func (n *Node) prepareENICreation(a *allocatableResources) (*types.Subnet, error) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if a.remainingInterfaces == 0 {
		// This is not a failure scenario, warn once per hour but do
		// not track as ENI allocation failure. There is a separate
		// metric to track nodes running at capacity.
		if time.Since(n.lastMaxAdapterWarning) > warningInterval {
			n.loggerLocked().WithFields(logrus.Fields{
				"max":       a.limits.Adapters,
				"allocated": a.totalENIs,
			}).Warning("Instance is out of ENIs")
			n.lastMaxAdapterWarning = time.Now()
		}
		return nil, nil
	}

	bestSubnet := n.manager.instancesAPI.FindSubnetByTags(n.resource.Spec.ENI.VpcID, n.resource.Spec.ENI.AvailabilityZone, n.resource.Spec.ENI.SubnetTags)
	if bestSubnet == nil {
		n.manager.metricsAPI.IncENIAllocationAttempt("no available subnet", "")
		return nil, fmt.Errorf("No matching subnet available for ENI creation (VPC=%s AZ=%s SubnetTags=%s",
			n.resource.Spec.ENI.VpcID, n.resource.Spec.ENI.AvailabilityZone, n.resource.Spec.ENI.SubnetTags)
	}

	return bestSubnet, nil
}

// maintainIpPool attempts to allocate or release all required IPs to fulfill
// the needed gap. If required, ENIs are created.
func (n *Node) maintainIpPool(ctx context.Context) error {
	a, err := n.determineMaintenanceAction()
	if err != nil {
		return err
	}

	// Maintenance request has already been fulfilled
	if a == nil {
		return nil
	}

	scopedLog := n.logger()

	// Release excess addresses
	if a.ipsToReleaseOnENI != nil {
		err := n.manager.ec2API.UnassignPrivateIpAddresses(ctx, n.enis[a.eni].ID, a.ipsToReleaseOnENI)
		if err == nil {
			n.manager.metricsAPI.AddIPRelease(a.subnet.ID, int64(a.availableOnSubnet))
			return nil
		}
		n.manager.metricsAPI.IncENIAllocationAttempt("ip unassignment failed", a.subnet.ID)
		scopedLog.WithFields(logrus.Fields{
			fieldEniID:           n.enis[a.eni].ID,
			"releasingAddresses": a.ipsToReleaseOnENI,
		}).WithError(err).Warning("Unable to unassign private IPs from ENI")
		return err
	}

	// Assign needed addresses
	if a.subnet != nil && a.availableOnSubnet > 0 {
		err := n.manager.ec2API.AssignPrivateIpAddresses(ctx, n.enis[a.eni].ID, int64(a.availableOnSubnet))
		if err == nil {
			n.manager.metricsAPI.IncENIAllocationAttempt("success", a.subnet.ID)
			n.manager.metricsAPI.AddIPAllocation(a.subnet.ID, int64(a.availableOnSubnet))
			return nil
		}

		n.manager.metricsAPI.IncENIAllocationAttempt("ip assignment failed", a.subnet.ID)
		scopedLog.WithFields(logrus.Fields{
			fieldEniID:           n.enis[a.eni].ID,
			"requestedAddresses": a.availableOnSubnet,
		}).WithError(err).Warning("Unable to assign additional private IPs to ENI, will create new ENI")
	}

	bestSubnet, err := n.prepareENICreation(a)
	if err != nil {
		return err
	}

	// Out of ENIs
	if bestSubnet == nil {
		return nil
	}

	return n.allocateENI(ctx, bestSubnet, a)
}

// MaintainIpPool attempts to allocate or release all required IPs to fulfill
// the needed gap. If required, ENIs are created.
func (n *Node) MaintainIpPool(ctx context.Context) error {
	// If the instance is no longer running, don't attempt any deficit
	// resolution and wait for the custom resource to be updated as a sign
	// of life.
	n.mutex.RLock()
	if n.instanceNotRunning {
		n.mutex.RUnlock()
		return nil
	}
	n.mutex.RUnlock()

	err := n.maintainIpPool(ctx)
	n.mutex.Lock()
	if err == nil {
		n.loggerLocked().Debug("Setting resync needed")
		n.resyncNeeded = time.Now()
	}
	n.recalculateLocked()
	n.waitingForPoolMaintenance = false
	n.mutex.Unlock()
	n.manager.resyncTrigger.Trigger()
	return err
}

// SyncToAPIServer is called to synchronize the node content with the custom
// resource in the apiserver
func (n *Node) SyncToAPIServer() (err error) {
	var updatedNode *v2.CiliumNode

	scopedLog := n.logger()
	scopedLog.Debug("Refreshing node")

	node := n.ResourceCopy()
	origNode := node.DeepCopy()

	// Always update the status first to ensure that the ENI information is
	// synced for all addresses that are marked as available.
	//
	// Two attempts are made in case the local resource is outdated. If the
	// second attempt fails as well we are likely under heavy contention,
	// fall back to the controller based background interval to retry.
	for retry := 0; retry < 2; retry++ {
		if node.Status.IPAM.Used == nil {
			node.Status.IPAM.Used = map[string]v2.AllocationIP{}
		}

		node.Status.ENI.ENIs = n.ENIs()

		scopedLog.WithFields(logrus.Fields{
			"numENIs":      len(node.Status.ENI.ENIs),
			"allocatedIPs": len(node.Status.IPAM.Used),
		}).Debug("Updating status of node in apiserver")

		updatedNode, err = n.manager.k8sAPI.UpdateStatus(node, origNode)
		if updatedNode != nil && updatedNode.Name != "" {
			node = updatedNode.DeepCopy()
			if err == nil {
				break
			}
		} else if err != nil {
			node, err = n.manager.k8sAPI.Get(node.Name)
			if err != nil {
				break
			}
			node = node.DeepCopy()
			origNode = node.DeepCopy()
		} else {
			break
		}
	}

	if err != nil {
		scopedLog.WithError(err).Warning("Unable to update CiliumNode status")
		return err
	}

	for retry := 0; retry < 2; retry++ {
		if node.Spec.IPAM.Pool == nil {
			node.Spec.IPAM.Pool = map[string]v2.AllocationIP{}
		}

		if node.Spec.ENI.PreAllocate == 0 {
			node.Spec.ENI.PreAllocate = defaults.ENIPreAllocation
		}

		node.Spec.IPAM.Pool = n.Pool()

		scopedLog.WithField("poolSize", len(node.Spec.IPAM.Pool)).Debug("Updating node in apiserver")

		updatedNode, err = n.manager.k8sAPI.Update(node, origNode)
		if updatedNode != nil && updatedNode.Name != "" {
			node = updatedNode.DeepCopy()
			if err == nil {
				break
			}
		} else if err != nil {
			node, err = n.manager.k8sAPI.Get(node.Name)
			if err != nil {
				break
			}
			node = node.DeepCopy()
			origNode = node.DeepCopy()
		} else {
			break
		}
	}

	if err != nil {
		scopedLog.WithError(err).Warning("Unable to update CiliumNode spec")
	}

	return err
}
