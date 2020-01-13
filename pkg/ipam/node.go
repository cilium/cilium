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
	"time"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/math"
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
	available map[string]v2.AllocationIP

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

// SetRunningLocked sets the running state of the node. This function assumes
// that the node is locked. It is intended to be used by implementations of
// NodeOperations which are called with the node in locked state.
func (n *Node) SetRunningLocked(running bool) {
	n.loggerLocked().Infof("Set running %t", running)
	n.instanceRunning = running
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

func (n *Node) loggerLocked() *logrus.Entry {
	if n == nil {
		return log
	}

	logger := log.WithField(fieldName, n.name)
	return n.ops.LogFields(logger)
}

// GetNeededAddresses returns the number of needed addresses that need to be
// allocated or released. A positive number is returned to indicate allocation.
// A negative number is returned to indicate release of addresses.
func (n *Node) GetNeededAddresses() int {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	if n.stats.NeededIPs > 0 {
		return n.stats.NeededIPs
	}
	if n.manager.releaseExcessIPs && n.stats.ExcessIPs > 0 {
		// Nodes are sorted by needed addresses, return negative values of excessIPs
		// so that nodes with IP deficit are resolved first
		return n.stats.ExcessIPs * -1
	}
	return 0
}

func calculateNeededIPs(availableIPs, usedIPs, preAllocate, minAllocate int) (neededIPs int) {
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

// UpdatedResource is called when an update to the CiliumNode has been
// received. The IPAM layer will attempt to immediately resolve any IP deficits
// and also trigger the background sync to continue working in the background
// to resolve any deficits or excess.
func (n *Node) UpdatedResource(resource *v2.CiliumNode) bool {
	// Deep copy the resource before storing it. This way we are not
	// dependent on caller not using the resource after this call.
	resource = resource.DeepCopy()

	n.mutex.Lock()
	n.ops.UpdatedNode(resource)

	// Any modification to the custom resource is seen as a sign that the
	// instance is alive
	if !n.instanceRunning {
		n.instanceRunning = true
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
	scopedLog := n.loggerLocked()
	a, err := n.ops.ResyncInterfacesAndIPs(context.TODO(), scopedLog)
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
	n.stats.NeededIPs = calculateNeededIPs(n.stats.AvailableIPs, n.stats.UsedIPs, n.ops.GetPreAllocate(), n.ops.GetMinAllocate())
	n.stats.ExcessIPs = calculateExcessIPs(n.stats.AvailableIPs, n.stats.UsedIPs, n.ops.GetPreAllocate(), n.ops.GetMinAllocate(), n.ops.GetMaxAboveWatermark())

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
func (n *Node) allocationNeeded() bool {
	return !n.waitingForPoolMaintenance && n.resyncNeeded.IsZero() && n.stats.NeededIPs > 0
}

// releaseNeeded returns true if this node requires IPs to be released
func (n *Node) releaseNeeded() bool {
	return n.manager.releaseExcessIPs && !n.waitingForPoolMaintenance && n.resyncNeeded.IsZero() && n.stats.ExcessIPs > 0
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

// createInterface creates an additional interface with the instance and
// attaches it to the instance as specified by the CiliumNode. neededAddresses
// of secondary IPs are assigned to the interface up to the maximum number of
// addresses as allowed by the instance.
func (n *Node) createInterface(ctx context.Context, a *AllocationAction) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if a.AvailableInterfaces == 0 {
		// This is not a failure scenario, warn once per hour but do
		// not track as interface allocation failure. There is a
		// separate metric to track nodes running at capacity.
		if time.Since(n.lastMaxAdapterWarning) > warningInterval {
			n.loggerLocked().Warning("Instance is out of interfaces")
			n.lastMaxAdapterWarning = time.Now()
		}
		return nil
	}

	scopedLog := n.loggerLocked()
	toAllocate, errCondition, err := n.ops.CreateInterface(ctx, a, scopedLog)
	if err != nil {
		scopedLog.Warningf("Unable to create interface on instance %s: %s", n.name, err)
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

	// PoolID is the IPAM pool identifier to allocate the IPs from. This
	// can correspond to a subnet ID or it can also left blank or set to a
	// value such as "global" to indicate a single address pool.
	PoolID PoolID

	// AvailableForAllocation is the number IPs available for allocation.
	// If InterfaeID is set, then this number corresponds to the number of
	// IPs available for allocation on that interface. This number may be
	// lower than the number of IPs required to resolve the deficit.
	AvailableForAllocation int

	// MaxIPsToAllocate is set by the core IPAM layer before
	// NodeOperations.AllocateIPs() is called and defines the maximum
	// number of IPs to allocate in order to stay within the boundaries as
	// defined by NodeOperations.{ MinAllocate() | PreAllocate() |
	// GetMaxAboveWatermark() }.
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
	PoolID PoolID

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

	n.mutex.Lock()
	defer n.mutex.Unlock()

	a := &maintenanceAction{}
	scopedLog := n.loggerLocked()

	// Validate that the node still requires addresses to be released, the
	// request may have been resolved in the meantime.
	if n.manager.releaseExcessIPs && n.stats.ExcessIPs > 0 {
		a.release = n.ops.PrepareIPRelease(n.stats.ExcessIPs, scopedLog)
		scopedLog = scopedLog.WithFields(logrus.Fields{
			"available":         n.stats.AvailableIPs,
			"used":              n.stats.UsedIPs,
			"excess":            n.stats.ExcessIPs,
			"releasing":         a.release.IPsToRelease,
			"selectedInterface": a.release.InterfaceID,
			"selectedPoolID":    a.release.PoolID,
		})
		scopedLog.Info("Releasing excess IPs from node")
		return a, nil
	}

	// Validate that the node still requires addresses to be allocated, the
	// request may have been resolved in the meantime.
	if n.stats.NeededIPs == 0 {
		return nil, nil
	}

	a.allocation, err = n.ops.PrepareIPAllocation(scopedLog)
	if err != nil {
		return nil, err
	}

	a.allocation.MaxIPsToAllocate = n.stats.NeededIPs + n.ops.GetMaxAboveWatermark()

	if a.allocation != nil {
		n.stats.RemainingInterfaces = a.allocation.AvailableInterfaces
		scopedLog = scopedLog.WithFields(logrus.Fields{
			"selectedInterface":      a.allocation.InterfaceID,
			"selectedPoolID":         a.allocation.PoolID,
			"maxIPsToAllocate":       a.allocation.MaxIPsToAllocate,
			"availableForAllocation": a.allocation.AvailableForAllocation,
			"availableInterfaces":    a.allocation.AvailableInterfaces,
		})
	}

	scopedLog.WithFields(logrus.Fields{
		"available":           n.stats.AvailableIPs,
		"used":                n.stats.UsedIPs,
		"neededIPs":           n.stats.NeededIPs,
		"remainingInterfaces": n.stats.RemainingInterfaces,
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

// MaintainIPPool attempts to allocate or release all required IPs to fulfill
// the needed gap. If required, interfaces are created.
func (n *Node) MaintainIPPool(ctx context.Context) error {
	// If the instance is no longer running, don't attempt any deficit
	// resolution and wait for the custom resource to be updated as a sign
	// of life.
	n.mutex.RLock()
	if !n.instanceRunning {
		n.mutex.RUnlock()
		return nil
	}
	n.mutex.RUnlock()

	err := n.maintainIPPool(ctx)
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

// syncToAPIServer is called to synchronize the node content with the custom
// resource in the apiserver
func (n *Node) syncToAPIServer() (err error) {
	var updatedNode *v2.CiliumNode

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
			node.Status.IPAM.Used = map[string]v2.AllocationIP{}
		}

		n.ops.PopulateStatusFields(node)
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

		node.Spec.IPAM.Pool = n.Pool()
		scopedLog.WithField("poolSize", len(node.Spec.IPAM.Pool)).Debug("Updating node in apiserver")

		n.ops.PopulateSpecFields(node)
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
