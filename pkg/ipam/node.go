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

package ipam

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/aws/eni/limits"
	"github.com/cilium/cilium/pkg/defaults"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/math"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"

	"github.com/sirupsen/logrus"
)

const (
	// warningInterval is the interval for warnings which should be done
	// once and then repeated if the warning persists.
	warningInterval = time.Hour
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
	stats Statistics

	// lastMaxAdapterWarning is the timestamp when the last warning was
	// printed that this node is out of adapters
	lastMaxAdapterWarning time.Time

	// instanceRunning is true when the EC2 instance backing the node is
	// not running. This state is detected based on error messages returned
	// when modifying instance state
	instanceRunning bool

	// instanceStoppedRunning records when an instance was most recently set to not running
	instanceStoppedRunning time.Time

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

	// available is the map of IPs available to this node
	available ipamTypes.AllocationMap

	// manager is the NodeManager responsible for this node
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

	// ops is the IPAM implementation to used for this node
	ops NodeOperations

	// retry is the trigger used to retry pool maintenance while the
	// instances API is unstable
	retry *trigger.Trigger
}

// Statistics represent the IP allocation statistics of a node
type Statistics struct {
	// UsedIPs is the number of IPs currently in use
	UsedIPs int

	// AvailableIPs is the number of IPs currently available for allocation
	// by the node
	AvailableIPs int

	// NeededIPs is the number of IPs needed to reach the PreAllocate
	// watermwark
	NeededIPs int

	// ExcessIPs is the number of free IPs exceeding MaxAboveWatermark
	ExcessIPs int

	// RemainingInterfaces is the number of interfaces that can either be
	// allocated or have not yet exhausted the instance specific quota of
	// addresses
	RemainingInterfaces int
}

// IsRunning returns true if the node is considered to be running
func (n *Node) IsRunning() bool {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	return n.instanceRunning
}

func (n *Node) SetRunning(running bool) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	n.loggerLocked().Infof("Set running %t", running)
	n.instanceRunning = running
	if !n.instanceRunning {
		n.instanceStoppedRunning = time.Now()
	}
}

// Stats returns a copy of the node statistics
func (n *Node) Stats() Statistics {
	n.mutex.RLock()
	c := n.stats
	n.mutex.RUnlock()
	return c
}

// Ops returns the IPAM implementation operations for the node
func (n *Node) Ops() NodeOperations {
	return n.ops
}

func (n *Node) logger() *logrus.Entry {
	if n == nil {
		return log
	}

	n.mutex.RLock()
	defer n.mutex.RUnlock()

	return n.loggerLocked()
}

func (n *Node) loggerLocked() (logger *logrus.Entry) {
	logger = log

	if n != nil {
		logger = logger.WithField(fieldName, n.name)
		if n.resource != nil {
			logger = logger.WithField("instanceID", n.resource.InstanceID())
		}
	}
	return
}

// getMaxAboveWatermark returns the max-above-watermark setting for an AWS node
//
// n.mutex must be held when calling this function
func (n *Node) getMaxAboveWatermark() int {
	if n.resource.Spec.IPAM.MaxAboveWatermark != 0 {
		return n.resource.Spec.IPAM.MaxAboveWatermark
	}
	// OBSOLETE: This can be removed in Cilium 1.9
	return n.resource.Spec.ENI.MaxAboveWatermark
}

// getPreAllocate returns the pre-allocation setting for an AWS node
//
// n.mutex must be held when calling this function
func (n *Node) getPreAllocate() int {
	if n.resource.Spec.IPAM.PreAllocate != 0 {
		return n.resource.Spec.IPAM.PreAllocate
	}
	// OBSOLETE: This can be removed in Cilium 1.9
	if n.resource.Spec.ENI.PreAllocate != 0 {
		return n.resource.Spec.ENI.PreAllocate
	}
	return defaults.IPAMPreAllocation
}

// getMinAllocate returns the minimum-allocation setting of an AWS node
//
// n.mutex must be held when calling this function
func (n *Node) getMinAllocate() int {
	if n.resource.Spec.IPAM.MinAllocate != 0 {
		return n.resource.Spec.IPAM.MinAllocate
	}
	// OBSOLETE: This can be removed in Cilium 1.9
	return n.resource.Spec.ENI.MinAllocate
}

// getMaxAllocate returns the maximum-allocation setting of an AWS node
func (n *Node) getMaxAllocate() int {
	instanceMax := n.ops.GetMaximumAllocatableIPv4()
	if n.resource.Spec.IPAM.MaxAllocate > 0 {
		if n.resource.Spec.IPAM.MaxAllocate > instanceMax {
			n.loggerLocked().Warningf("max-allocate (%d) is higher than the instance type limits (%d)", n.resource.Spec.IPAM.MaxAllocate, instanceMax)
		}
		return n.resource.Spec.IPAM.MaxAllocate
	}

	return instanceMax
}

// GetNeededAddresses returns the number of needed addresses that need to be
// allocated or released. A positive number is returned to indicate allocation.
// A negative number is returned to indicate release of addresses.
func (n *Node) GetNeededAddresses() int {
	stats := n.Stats()
	if stats.NeededIPs > 0 {
		return stats.NeededIPs
	}
	if n.manager.releaseExcessIPs && stats.ExcessIPs > 0 {
		// Nodes are sorted by needed addresses, return negative values of excessIPs
		// so that nodes with IP deficit are resolved first
		return stats.ExcessIPs * -1
	}
	return 0
}

func calculateNeededIPs(availableIPs, usedIPs, preAllocate, minAllocate, maxAllocate int) (neededIPs int) {
	neededIPs = preAllocate - (availableIPs - usedIPs)

	if minAllocate > 0 {
		neededIPs = math.IntMax(neededIPs, minAllocate-availableIPs)
	}

	// If maxAllocate is set (> 0) and neededIPs is higher than the
	// maxAllocate value, we only return the amount of IPs that can
	// still be allocated
	if maxAllocate > 0 && (availableIPs+neededIPs) > maxAllocate {
		neededIPs = maxAllocate - availableIPs
	}

	if neededIPs < 0 {
		neededIPs = 0
	}

	return
}

func calculateExcessIPs(availableIPs, usedIPs, preAllocate, minAllocate, maxAboveWatermark int) (excessIPs int) {
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

func (n *Node) requirePoolMaintenance() {
	n.mutex.Lock()
	n.waitingForPoolMaintenance = true
	n.mutex.Unlock()
}

func (n *Node) poolMaintenanceComplete() {
	n.mutex.Lock()
	n.waitingForPoolMaintenance = false
	n.mutex.Unlock()
}

// InstanceID returns the instance ID of the node
func (n *Node) InstanceID() (id string) {
	n.mutex.RLock()
	if n.resource != nil {
		id = n.resource.InstanceID()
	}
	n.mutex.RUnlock()
	return
}

// UpdatedResource is called when an update to the CiliumNode has been
// received. The IPAM layer will attempt to immediately resolve any IP deficits
// and also trigger the background sync to continue working in the background
// to resolve any deficits or excess.
func (n *Node) UpdatedResource(resource *v2.CiliumNode) bool {
	// Deep copy the resource before storing it. This way we are not
	// dependent on caller not using the resource after this call.
	resource = resource.DeepCopy()

	n.ops.UpdatedNode(resource)

	n.mutex.Lock()
	// Any modification to the custom resource is seen as a sign that the
	// instance is alive
	n.instanceRunning = true
	n.resource = resource
	n.mutex.Unlock()

	n.recalculate()
	allocationNeeded := n.allocationNeeded()
	if allocationNeeded {
		n.requirePoolMaintenance()
		n.poolMaintainer.Trigger()
	}

	return allocationNeeded
}

func (n *Node) resourceAttached() (attached bool) {
	n.mutex.RLock()
	attached = n.resource != nil
	n.mutex.RUnlock()
	return
}

func (n *Node) recalculate() {
	// Skip any recalculation if the CiliumNode resource does not exist yet
	if !n.resourceAttached() {
		return
	}
	scopedLog := n.logger()

	a, err := n.ops.ResyncInterfacesAndIPs(context.TODO(), scopedLog)

	n.mutex.Lock()
	defer n.mutex.Unlock()

	if err != nil {
		scopedLog.Warning("Instance not found! Please delete corresponding ciliumnode if instance has already been deleted.")
		// Avoid any further action
		n.stats.NeededIPs = 0
		n.stats.ExcessIPs = 0
		return
	}

	n.available = a
	n.stats.UsedIPs = len(n.resource.Status.IPAM.Used)
	n.stats.AvailableIPs = len(n.available)
	n.stats.NeededIPs = calculateNeededIPs(n.stats.AvailableIPs, n.stats.UsedIPs, n.getPreAllocate(), n.getMinAllocate(), n.getMaxAllocate())
	n.stats.ExcessIPs = calculateExcessIPs(n.stats.AvailableIPs, n.stats.UsedIPs, n.getPreAllocate(), n.getMinAllocate(), n.getMaxAboveWatermark())

	scopedLog.WithFields(logrus.Fields{
		"available":                 n.stats.AvailableIPs,
		"used":                      n.stats.UsedIPs,
		"toAlloc":                   n.stats.NeededIPs,
		"toRelease":                 n.stats.ExcessIPs,
		"waitingForPoolMaintenance": n.waitingForPoolMaintenance,
		"resyncNeeded":              n.resyncNeeded,
	}).Debug("Recalculated needed addresses")
}

// allocationNeeded returns true if this node requires IPs to be allocated
func (n *Node) allocationNeeded() (needed bool) {
	n.mutex.RLock()
	needed = !n.waitingForPoolMaintenance && n.resyncNeeded.IsZero() && n.stats.NeededIPs > 0
	n.mutex.RUnlock()
	return
}

// releaseNeeded returns true if this node requires IPs to be released
func (n *Node) releaseNeeded() (needed bool) {
	n.mutex.RLock()
	needed = n.manager.releaseExcessIPs && !n.waitingForPoolMaintenance && n.resyncNeeded.IsZero() && n.stats.ExcessIPs > 0
	n.mutex.RUnlock()
	return
}

// Pool returns the IP allocation pool available to the node
func (n *Node) Pool() (pool ipamTypes.AllocationMap) {
	pool = ipamTypes.AllocationMap{}
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

// createInterface creates an additional interface with the instance and
// attaches it to the instance as specified by the CiliumNode. neededAddresses
// of secondary IPs are assigned to the interface up to the maximum number of
// addresses as allowed by the instance.
func (n *Node) createInterface(ctx context.Context, a *AllocationAction) error {
	if a.AvailableInterfaces == 0 {
		// This is not a failure scenario, warn once per hour but do
		// not track as interface allocation failure. There is a
		// separate metric to track nodes running at capacity.
		n.mutex.Lock()
		if time.Since(n.lastMaxAdapterWarning) > warningInterval {
			n.loggerLocked().Warning("Instance is out of interfaces")
			n.lastMaxAdapterWarning = time.Now()
		}
		n.mutex.Unlock()
		return nil
	}

	scopedLog := n.logger()
	toAllocate, errCondition, err := n.ops.CreateInterface(ctx, a, scopedLog)
	if err != nil {
		scopedLog.Warningf("Unable to create interface on instance: %s", err)
		n.manager.metricsAPI.IncAllocationAttempt(errCondition, string(a.PoolID))
		return err
	}

	n.manager.metricsAPI.IncAllocationAttempt("success", string(a.PoolID))
	n.manager.metricsAPI.AddIPAllocation(string(a.PoolID), int64(toAllocate))

	return nil
}

// AllocationAction is the action to be taken to resolve allocation deficits
// for a particular node. It is returned by
// NodeOperations.PrepareIPAllocation() and passed into
// NodeOperations.AllocateIPs().
type AllocationAction struct {
	// InterfaceID is set to the identifier describing the interface on
	// which the IPs must be allocated. This is optional, an IPAM
	// implementation can leave this empty to indicate that no interface
	// context is needed or a new interface must be created.
	InterfaceID string

	// Interface is the interface to allocate IPs on
	Interface ipamTypes.InterfaceRevision

	// PoolID is the IPAM pool identifier to allocate the IPs from. This
	// can correspond to a subnet ID or it can also left blank or set to a
	// value such as "global" to indicate a single address pool.
	PoolID ipamTypes.PoolID

	// AvailableForAllocation is the number IPs available for allocation.
	// If InterfaeID is set, then this number corresponds to the number of
	// IPs available for allocation on that interface. This number may be
	// lower than the number of IPs required to resolve the deficit.
	AvailableForAllocation int

	// MaxIPsToAllocate is set by the core IPAM layer before
	// NodeOperations.AllocateIPs() is called and defines the maximum
	// number of IPs to allocate in order to stay within the boundaries as
	// defined by NodeOperations.{ MinAllocate() | PreAllocate() |
	// getMaxAboveWatermark() }.
	MaxIPsToAllocate int

	// AvailableInterfaces is the number of interfaces available to be created
	AvailableInterfaces int
}

// ReleaseAction is the action to be taken to resolve allocation excess for a
// particular node. It is returned by NodeOperations.PrepareIPRelease() and
// passed into NodeOperations.ReleaseIPs().
type ReleaseAction struct {
	// InterfaceID is set to the identifier describing the interface on
	// which the IPs must be released. This is optional, an IPAM
	// implementation can leave this empty to indicate that no interface
	// context is needed.
	InterfaceID string

	// PoolID is the IPAM pool identifier to release the IPs from. This can
	// correspond to a subnet ID or it can also left blank or set to a
	// value such as "global" to indicate a single address pool.
	PoolID ipamTypes.PoolID

	// IPsToRelease is the list of IPs to release
	IPsToRelease []string
}

// maintenanceAction represents the resources available for allocation for a
// particular ciliumNode. If an existing interface has IP allocation capacity
// left, that capacity is used up first. If not, an available index is found to
// create a new interface.
type maintenanceAction struct {
	allocation *AllocationAction
	release    *ReleaseAction
}

func (n *Node) determineMaintenanceAction() (*maintenanceAction, error) {
	var err error

	a := &maintenanceAction{}

	scopedLog := n.logger()
	stats := n.Stats()

	// Validate that the node still requires addresses to be released, the
	// request may have been resolved in the meantime.
	if n.manager.releaseExcessIPs && stats.ExcessIPs > 0 {
		a.release = n.ops.PrepareIPRelease(stats.ExcessIPs, scopedLog)
		scopedLog = scopedLog.WithFields(logrus.Fields{
			"available":         stats.AvailableIPs,
			"used":              stats.UsedIPs,
			"excess":            stats.ExcessIPs,
			"releasing":         a.release.IPsToRelease,
			"selectedInterface": a.release.InterfaceID,
			"selectedPoolID":    a.release.PoolID,
		})
		scopedLog.Info("Releasing excess IPs from node")
		return a, nil
	}

	// Validate that the node still requires addresses to be allocated, the
	// request may have been resolved in the meantime.
	if stats.NeededIPs == 0 {
		return nil, nil
	}

	a.allocation, err = n.ops.PrepareIPAllocation(scopedLog)
	if err != nil {
		return nil, err
	}

	n.mutex.RLock()
	a.allocation.MaxIPsToAllocate = stats.NeededIPs + n.getMaxAboveWatermark()
	n.mutex.RUnlock()

	if a.allocation != nil {
		n.mutex.Lock()
		n.stats.RemainingInterfaces = a.allocation.AvailableInterfaces
		stats = n.stats
		n.mutex.Unlock()
		scopedLog = scopedLog.WithFields(logrus.Fields{
			"selectedInterface":      a.allocation.InterfaceID,
			"selectedPoolID":         a.allocation.PoolID,
			"maxIPsToAllocate":       a.allocation.MaxIPsToAllocate,
			"availableForAllocation": a.allocation.AvailableForAllocation,
			"availableInterfaces":    a.allocation.AvailableInterfaces,
		})
	}

	scopedLog.WithFields(logrus.Fields{
		"available":           stats.AvailableIPs,
		"used":                stats.UsedIPs,
		"neededIPs":           stats.NeededIPs,
		"remainingInterfaces": stats.RemainingInterfaces,
	}).Info("Resolving IP deficit of node")

	return a, nil
}

// maintainIPPool attempts to allocate or release all required IPs to fulfill
// the needed gap.
func (n *Node) maintainIPPool(ctx context.Context) error {
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
	if a.release != nil && len(a.release.IPsToRelease) > 0 {
		err := n.ops.ReleaseIPs(ctx, a.release)
		if err == nil {
			n.manager.metricsAPI.AddIPRelease(string(a.release.PoolID), int64(len(a.release.IPsToRelease)))
			return nil
		}
		n.manager.metricsAPI.IncAllocationAttempt("ip unassignment failed", string(a.release.PoolID))
		scopedLog.WithFields(logrus.Fields{
			"selectedInterface":  a.release.InterfaceID,
			"releasingAddresses": len(a.release.IPsToRelease),
		}).WithError(err).Warning("Unable to unassign IPs from interface")
		return err
	}

	if a.allocation == nil {
		scopedLog.Debug("No allocation action required")
		return nil
	}

	// Assign needed addresses
	if a.allocation.AvailableForAllocation > 0 {
		a.allocation.AvailableForAllocation = math.IntMin(a.allocation.AvailableForAllocation, a.allocation.MaxIPsToAllocate)

		err := n.ops.AllocateIPs(ctx, a.allocation)
		if err == nil {
			n.manager.metricsAPI.IncAllocationAttempt("success", string(a.allocation.PoolID))
			n.manager.metricsAPI.AddIPAllocation(string(a.allocation.PoolID), int64(a.allocation.AvailableForAllocation))
			return nil
		}

		n.manager.metricsAPI.IncAllocationAttempt("ip assignment failed", string(a.allocation.PoolID))
		scopedLog.WithFields(logrus.Fields{
			"selectedInterface": a.allocation.InterfaceID,
			"ipsToAllocate":     a.allocation.AvailableForAllocation,
		}).WithError(err).Warning("Unable to assign additional IPs to interface, will create new interface")
	}

	return n.createInterface(ctx, a.allocation)
}

func (n *Node) isInstanceRunning() (isRunning bool) {
	n.mutex.RLock()
	isRunning = n.instanceRunning
	n.mutex.RUnlock()
	return
}

func (n *Node) requireResync() {
	n.mutex.Lock()
	n.resyncNeeded = time.Now()
	n.mutex.Unlock()
}

func (n *Node) updateLastResync(syncTime time.Time) {
	n.mutex.Lock()
	if syncTime.After(n.resyncNeeded) {
		n.loggerLocked().Debug("Resetting resyncNeeded")
		n.resyncNeeded = time.Time{}
	}
	n.mutex.Unlock()
}

// MaintainIPPool attempts to allocate or release all required IPs to fulfill
// the needed gap. If required, interfaces are created.
func (n *Node) MaintainIPPool(ctx context.Context) error {
	// As long as the instances API is unstable, don't perform any
	// operation that can mutate state.
	if !n.manager.InstancesAPIIsReady() {
		if n.retry != nil {
			n.retry.Trigger()
		}
		return fmt.Errorf("instances API is unstable. Blocking mutating operations. See logs for details.")
	}

	// If the instance has stopped running for less than a minute, don't attempt any deficit
	// resolution and wait for the custom resource to be updated as a sign
	// of life.
	if !n.isInstanceRunning() && n.instanceStoppedRunning.Add(time.Minute).After(time.Now()) {
		return nil
	}

	err := n.maintainIPPool(ctx)
	if err == nil {
		n.logger().Debug("Setting resync needed")
		n.requireResync()
	}
	n.poolMaintenanceComplete()
	n.recalculate()
	n.manager.resyncTrigger.Trigger()
	return err
}

// syncToAPIServer synchronizes the contents of the CiliumNode resource
// [(*Node).resource)] with the K8s apiserver. This operation occurs on an
// interval to refresh the CiliumNode resource.
//
// For Azure and ENI IPAM modes, this function serves two purposes: (1) as the
// entry point to initialize the CiliumNode resource and (2) to keep the
// resource up-to-date with K8s.
//
// To initialize, or seed, the CiliumNode resource, the PreAllocate field is
// populated with a default value and then is adjusted as necessary.
func (n *Node) syncToAPIServer() (err error) {
	scopedLog := n.logger()
	scopedLog.Debug("Refreshing node")

	node := n.ResourceCopy()
	// n.resource may not have been assigned yet
	if node == nil {
		return
	}

	origNode := node.DeepCopy()

	// Always update the status first to ensure that the IPAM information
	// is synced for all addresses that are marked as available.
	//
	// Two attempts are made in case the local resource is outdated. If the
	// second attempt fails as well we are likely under heavy contention,
	// fall back to the controller based background interval to retry.
	for retry := 0; retry < 2; retry++ {
		if node.Status.IPAM.Used == nil {
			node.Status.IPAM.Used = ipamTypes.AllocationMap{}
		}

		n.ops.PopulateStatusFields(node)

		err = n.update(origNode, node, retry, true)
		if err == nil {
			break
		}
	}

	if err != nil {
		scopedLog.WithError(err).Warning("Unable to update CiliumNode status")
		return err
	}

	for retry := 0; retry < 2; retry++ {
		if node.Spec.IPAM.Pool == nil {
			node.Spec.IPAM.Pool = ipamTypes.AllocationMap{}
		}

		node.Spec.IPAM.Pool = n.Pool()
		scopedLog.WithField("poolSize", len(node.Spec.IPAM.Pool)).Debug("Updating node in apiserver")

		if node.Spec.IPAM.PreAllocate == 0 {
			adjustPreAllocateIfNeeded(node)
		}

		err = n.update(origNode, node, retry, false)
		if err == nil {
			break
		}
	}

	if err != nil {
		scopedLog.WithError(err).Warning("Unable to update CiliumNode spec")
	}

	return err
}

// update is a helper function for syncToAPIServer(). This function updates the
// CiliumNode resource spec or status depending on `status`. The resource is
// updated from `origNode` to `node`.
//
// Note that the `origNode` and `node` pointers will have their underlying
// values modified in this function! The following is an outline of when
// `origNode` and `node` pointers are updated:
//  * `node` is updated when we succeed in updating to update the resource to
//     the apiserver.
//  * `origNode` and `node` are updated when we fail to update the resource,
//     but we succeed in retrieving the latest version of it from the
//     apiserver.
func (n *Node) update(origNode, node *v2.CiliumNode, attempts int, status bool) error {
	scopedLog := n.logger()

	var (
		updatedNode    *v2.CiliumNode
		updateErr, err error
	)

	if status {
		updatedNode, updateErr = n.manager.k8sAPI.UpdateStatus(origNode, node)
	} else {
		updatedNode, updateErr = n.manager.k8sAPI.Update(origNode, node)
	}

	if updatedNode != nil && updatedNode.Name != "" {
		*node = *updatedNode
		if updateErr == nil {
			return nil
		}
	} else if updateErr != nil {
		scopedLog.WithError(updateErr).WithFields(logrus.Fields{
			logfields.Attempt: attempts,
		}).Warning("Failed to update CiliumNode spec")

		var newNode *v2.CiliumNode
		newNode, err = n.manager.k8sAPI.Get(node.Name)
		if err != nil {
			return err
		}

		// Propagate the error in the case that we are on our last attempt and
		// we never succeeded in updating the resource.
		//
		// Also, propagate the reference to the nodes in the case we've
		// succeeded in updating the CiliumNode status. The reason is because
		// the subsequent run will be to update the CiliumNode spec and we need
		// to ensure we have the most up-to-date CiliumNode references before
		// doing that operation, hence the deep copies.
		err = updateErr
		*node = *newNode
		*origNode = *node
	} else /* updateErr == nil */ {
		err = updateErr
	}

	return err
}

// adjustPreAllocateIfNeeded adjusts IPAM values depending on the instance
// type. This is needed when the instance type is on the smaller side which
// requires us to lower the PreAllocate value and include eth0 as an ENI device
// because the instance type does not allow for additional ENIs to be attached
// (hence limited).
//
// For now, this function is only needed in ENI IPAM mode. In the future, this
// may also be needed for Azure IPAM as well.
func adjustPreAllocateIfNeeded(node *v2.CiliumNode) {
	if option.Config.IPAM != ipamOption.IPAMENI {
		return
	}

	// Auto set the PreAllocate to the default value and we'll determine if we
	// need to adjust it below.
	node.Spec.IPAM.PreAllocate = defaults.IPAMPreAllocation

	if lim, ok := limits.Get(node.Spec.ENI.InstanceType); ok {
		max := lim.Adapters * lim.IPv4
		if node.Spec.IPAM.PreAllocate > max {
			node.Spec.IPAM.PreAllocate = max

			var i int = 0
			node.Spec.ENI.FirstInterfaceIndex = &i // Include eth0
		}
	}
}
