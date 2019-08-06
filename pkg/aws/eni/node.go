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
	"fmt"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/math"
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

	// waitingForAllocation is true when the node is subject to an
	// allocation which must be performed before another allocation can be
	// attempted
	waitingForAllocation bool

	// resyncNeeded is set to the current time when a resync with the EC2
	// API is required. The timestamp is required to ensure that this is
	// only reset if the resync started after the time stored in
	// resyncNeeded. This is needed because resyncs and allocations happen
	// in parallel.
	resyncNeeded time.Time

	enis map[string]v2.ENI

	available map[string]v2.AllocationIP

	manager *NodeManager

	// deficitResolver is the trigger used to resolve a deficit of this
	// node. It ensures that multiple requests to resolve a deficit are
	// batched together if deficit resolution is still ongoing.
	deficitResolver *trigger.Trigger

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

	return n.stats.neededIPs
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

func (n *Node) updatedResource(resource *v2.CiliumNode) bool {
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
		n.waitingForAllocation = true
		n.deficitResolver.Trigger()
	}
	n.mutex.Unlock()

	return allocationNeeded
}

func (n *Node) recalculateLocked() {
	n.enis = map[string]v2.ENI{}
	n.available = map[string]v2.AllocationIP{}
	for _, e := range n.manager.instancesAPI.GetENIs(n.resource.Spec.ENI.InstanceID) {
		n.enis[e.ID] = *e

		if e.Number < n.resource.Spec.ENI.FirstInterfaceIndex {
			continue
		}

		for _, ip := range e.Addresses {
			n.available[ip] = v2.AllocationIP{Resource: e.ID}
		}
	}
	n.stats.usedIPs = len(n.resource.Status.IPAM.Used)
	n.stats.availableIPs = len(n.available)
	n.stats.neededIPs = calculateNeededIPs(n.stats.availableIPs, n.stats.usedIPs, n.resource.Spec.ENI.PreAllocate, n.resource.Spec.ENI.MinAllocate)

	n.loggerLocked().WithFields(logrus.Fields{
		"available":            n.stats.availableIPs,
		"used":                 n.stats.usedIPs,
		"toAlloc":              n.stats.neededIPs,
		"waitingForAllocation": n.waitingForAllocation,
		"resyncNeeded":         n.resyncNeeded,
	}).Debug("Recalculated needed addresses")
}

// allocationNeeded returns true if this node requires IPs to be allocated
func (n *Node) allocationNeeded() bool {
	return !n.waitingForAllocation && n.resyncNeeded.IsZero() && n.stats.neededIPs > 0
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

func (n *Node) getSecurityGroups() (securityGroups []string) {
	// When no security groups are provided, derive them from eth0
	securityGroups = n.resource.Spec.ENI.SecurityGroups
	if len(securityGroups) == 0 {
		if eni := n.manager.instancesAPI.GetENI(n.resource.Spec.ENI.InstanceID, 0); eni != nil {
			securityGroups = eni.SecurityGroups
		}
	}
	return
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
func (n *Node) allocateENI(s *types.Subnet, a *allocatableResources) error {
	nodeResource := n.ResourceCopy()
	n.mutex.RLock()
	securityGroups := n.getSecurityGroups()
	neededAddresses := n.stats.neededIPs

	desc := "Cilium-CNI (" + n.resource.Spec.ENI.InstanceID + ")"
	toAllocate := int64(math.IntMin(neededAddresses+nodeResource.Spec.ENI.MaxAboveWatermark, a.limits.IPv4))
	// Validate whether request has already been fulfilled in the meantime
	if toAllocate == 0 {
		n.mutex.RUnlock()
		return nil
	}

	index := n.findNextIndex(int64(nodeResource.Spec.ENI.FirstInterfaceIndex))

	scopedLog := n.loggerLocked().WithFields(logrus.Fields{
		"securityGroups": securityGroups,
		"subnetID":       s.ID,
		"addresses":      toAllocate,
	})
	scopedLog.Info("No more IPs available, creating new ENI")
	n.mutex.RUnlock()

	eniID, eni, err := n.manager.ec2API.CreateNetworkInterface(toAllocate, s.ID, desc, securityGroups)
	if err != nil {
		n.manager.metricsAPI.IncENIAllocationAttempt("ENI creation failed", s.ID)
		return fmt.Errorf("unable to create ENI: %s", err)
	}

	scopedLog = scopedLog.WithField(fieldEniID, eniID)
	scopedLog.Info("Created new ENI")

	var attachmentID string
	for attachRetries := 0; attachRetries < maxAttachRetries; attachRetries++ {
		attachmentID, err = n.manager.ec2API.AttachNetworkInterface(index, nodeResource.Spec.ENI.InstanceID, eniID)

		// The index is already in use, this can happen if the local
		// list of ENIs is oudated.  Retry the attachment to avoid
		// having to delete the ENI
		if !isAttachmentIndexConflict(err) {
			break
		}

		index = n.findNextIndex(index + 1)
	}

	if err != nil {
		delErr := n.manager.ec2API.DeleteNetworkInterface(eniID)
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

	if nodeResource.Spec.ENI.DeleteOnTermination {
		// We have an attachment ID from the last API, which lets us mark the
		// interface as delete on termination
		err = n.manager.ec2API.ModifyNetworkInterface(eniID, attachmentID, n.resource.Spec.ENI.DeleteOnTermination)
		if err != nil {
			delErr := n.manager.ec2API.DeleteNetworkInterface(eniID)
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
	eni                 *v2.ENI
	subnet              *types.Subnet
	availableOnSubnet   int
	limits              Limits
	remainingInterfaces int
	totalENIs           int
}

func (n *Node) determineAllocationAction() (*allocatableResources, error) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	// Validate that the node still requires addresses to be allocated, the
	// request may have been resolved in the meantime.
	maxAllocate := n.stats.neededIPs + n.resource.Spec.ENI.MaxAboveWatermark
	if maxAllocate == 0 {
		return nil, nil
	}

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
	for _, e := range n.enis {
		scopedLog.WithFields(logrus.Fields{
			fieldEniID:     e.ID,
			"needIndex":    n.resource.Spec.ENI.FirstInterfaceIndex,
			"index":        e.Number,
			"addressLimit": a.limits.IPv4,
			"numAddresses": len(e.Addresses),
		}).Debug("Considering ENI for allocation")

		if e.Number < n.resource.Spec.ENI.FirstInterfaceIndex {
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
			if subnet.AvailableAddresses > 0 && a.eni == nil {
				scopedLog.WithFields(logrus.Fields{
					"subnetID":           e.Subnet.ID,
					"availableAddresses": subnet.AvailableAddresses,
				}).Debug("Subnet has IPs available")
				a.eni = &e
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

	if a.eni != nil {
		scopedLog = scopedLog.WithFields(logrus.Fields{
			"selectedENI":          a.eni.ID,
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

// allocate attempts to allocate all required IPs to fulfill the needed gap
// n.neededAddresses. If required, ENIs are created.
func (n *Node) resolveIPDeficit() error {
	a, err := n.determineAllocationAction()
	if err != nil {
		return err
	}

	// Allocation request has already been fulfilled
	if a == nil {
		return nil
	}

	scopedLog := n.logger()

	if a.subnet != nil && a.availableOnSubnet > 0 {
		err := n.manager.ec2API.AssignPrivateIpAddresses(a.eni.ID, int64(a.availableOnSubnet))
		if err == nil {
			n.manager.metricsAPI.IncENIAllocationAttempt("success", a.subnet.ID)
			n.manager.metricsAPI.AddIPAllocation(a.subnet.ID, int64(a.availableOnSubnet))
			return nil
		}

		n.manager.metricsAPI.IncENIAllocationAttempt("ip assignment failed", a.subnet.ID)
		scopedLog.WithFields(logrus.Fields{
			fieldEniID:           a.eni.ID,
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

	return n.allocateENI(bestSubnet, a)
}

// ResolveIPDeficit attempts to allocate all required IPs to fulfill the needed
// gap n.neededAddresses. If required, ENIs are created.
func (n *Node) ResolveIPDeficit() error {
	// If the instance is no longer running, don't attempt any deficit
	// resolution and wait for the custom resource to be updated as a sign
	// of life.
	n.mutex.RLock()
	if n.instanceNotRunning {
		n.mutex.RUnlock()
		return nil
	}
	n.mutex.RUnlock()

	err := n.resolveIPDeficit()
	n.mutex.Lock()
	if err == nil {
		n.loggerLocked().Debug("Setting resync needed")
		n.resyncNeeded = time.Now()
	}
	n.recalculateLocked()
	n.waitingForAllocation = false
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
