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

package ipam

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/trigger"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
)

// k8sImplementation defines the interface used to interact with the k8s
// apiserver to retrieve and update the CiliumNode custom resource
type k8sImplementation interface {
	Update(origResource, newResource *v2.CiliumNode) (*v2.CiliumNode, error)
	UpdateStatus(origResource, newResource *v2.CiliumNode) (*v2.CiliumNode, error)
	Get(name string) (*v2.CiliumNode, error)
}

// PoolID is the type used to identify an IPAM pool
type PoolID string

// PoolQuota defines the limits of an IPAM pool
type PoolQuota struct {
	// AvailabilityZone is the availability zone in which the IPAM pool resides in
	AvailabilityZone string

	// AvailableIPs is the number of available IPs in the pool
	AvailableIPs int
}

// PoolQuotaMap is a map of pool quotas indexes by pool identifier
type PoolQuotaMap map[PoolID]PoolQuota

// AllocationLimits defines the pre-allocation limits in which IPAM operations
// are performed. This defines the size of the buffer a node will maintain to
// have IPs available for immediate use without requiring to perform IP
// allocation via an external component.
type AllocationLimits interface {
	// GetMaxAboveWatermark returns the maximum number of addresses to
	// allocate beyond the addresses needed to reach the PreAllocate
	// watermark.  Going above the watermark can help reduce the number of
	// API calls to allocate IPs, e.g. when a new interface is allocated,
	// as many secondary IPs as possible are allocated. Limiting the amount
	// can help reduce waste of IPs.
	GetMaxAboveWatermark() int

	// GetPreAllocate returns the number of IP addresses that must be
	// available for immediate use by the node. It defines the buffer of
	// addresses available immediately without requiring cilium-operator to
	// get involved.
	GetPreAllocate() int

	// GetMinAllocate returns the minimum number of IPs that must be
	// allocated when the node is first bootstrapped. It defines the
	// minimum base socket of addresses that must be available. After
	// reaching this watermark, the PreAllocate and MaxAboveWatermark logic
	// takes over to continue allocating IPs.
	GetMinAllocate() int
}

// NodeOperations is the interface an IPAM implementation must provide in order
// to provide IP allocation for a node. The structure implementing this API
// *must* be aware of the node connected to this implementation. This is
// achieved by considering the node context provided in
// AllocationImplementation.CreateNode() function and returning a
// NodeOperations implementation which performs operations in the context of
// that node.
type NodeOperations interface {
	AllocationLimits

	// UpdateNode is called when an update to the CiliumNode is received.
	// Node.mutex will remain locked while UpdateNode is being called.
	UpdatedNode(obj *v2.CiliumNode)

	// PopulateStatusFields is called to give the implementation a chance
	// to populate any implementation specific fields in CiliumNode.Status.
	// Node.mutex will remain locked while this function is called.
	PopulateStatusFields(resource *v2.CiliumNode)

	// PopulateSpecFields is called to give the implementation a chance
	// to populate any implementation specific fields in CiliumNode.Spec.
	// Node.mutex will remain locked while this function is called.
	PopulateSpecFields(resource *v2.CiliumNode)

	// LogFields is called to extend the logrus logger with implementation
	// specific fields.  Node.mutex will remain locked while this function
	// is called.
	LogFields(log *logrus.Entry) *logrus.Entry

	// CreateInterface is called to create a new interface. This is only
	// done if PrepareIPAllocation indicates that no more IPs are available
	// (AllocationAction.AvailableForAllocation == 0) for allocation but
	// interfaces are available for creation
	// (AllocationAction.AvailableInterfaces > 0). This function must
	// create the interface *and* allocate up to
	// AllocationAction.MaxIPsToAllocate.  Node.mutex will remain locked
	// while this function is called.
	CreateInterface(ctx context.Context, allocation *AllocationAction, scopedLog *logrus.Entry) (int, string, error)

	// ResyncInterfacesAndIPs is called to synchronize the latest list of
	// interfaces and IPs associated with the node. This function is called
	// sparingly as this information is kept in sync based on the success
	// of the functions AllocateIPs(), ReleaseIPs() and CreateInterface().
	// Node.mutex will remain locked while this function is called.
	ResyncInterfacesAndIPs(ctx context.Context, scopedLog *logrus.Entry) (map[string]v2.AllocationIP, error)

	// PrepareIPAllocation is called to calculate the number of IPs that
	// can be allocated on the node and whether a new network interface
	// must be attached to the node. Node.mutex will remain locked while
	// this function is called.
	PrepareIPAllocation(scopedLog *logrus.Entry) (*AllocationAction, error)

	// AllocateIPs is called after invoking PrepareIPAllocation and needs
	// to perform the actual allocation.
	AllocateIPs(ctx context.Context, allocation *AllocationAction) error

	// PrepareIPRelease is called to calculate whether any IP excess needs
	// to be resolved. It behaves identical to PrepareIPAllocation but
	// indicates a need to release IPs.
	PrepareIPRelease(excessIPs int, scopedLog *logrus.Entry) *ReleaseAction

	// ReleaseIPs is called after invoking PrepareIPRelease and needs to
	// perform the release of IPs.
	ReleaseIPs(ctx context.Context, release *ReleaseAction) error
}

// AllocationImplementation is the interface an implementation must provide.
// Other than NodeOperations, this implementation is not related to a node
// specifically.
type AllocationImplementation interface {
	// CreateNode is called when the IPAM layer has learned about a new
	// node which requires IPAM services. This function must return a
	// NodeOperations implementation which will render IPAM services to the
	// node context provided.
	CreateNode(obj *v2.CiliumNode, node *Node) NodeOperations

	// GetPoolQuota is called to retrieve the remaining IP addresses in all
	// IP pools known to the IPAM implementation.
	GetPoolQuota() PoolQuotaMap

	// Resync is called periodically to give the IPAM implementation a
	// chance to resync its own state with external APIs or systems. It is
	// also called when the IPAM layer detects that state got out of sync.
	Resync(ctx context.Context) time.Time
}

type metricsAPI interface {
	IncAllocationAttempt(status, subnetID string)
	AddIPAllocation(subnetID string, allocated int64)
	AddIPRelease(subnetID string, released int64)
	SetAllocatedIPs(typ string, allocated int)
	SetAvailableENIs(available int)
	SetAvailableIPsPerSubnet(subnetID string, availabilityZone string, available int)
	SetNodes(category string, nodes int)
	IncResyncCount()
	PoolMaintainerTrigger() trigger.MetricsObserver
	K8sSyncTrigger() trigger.MetricsObserver
	ResyncTrigger() trigger.MetricsObserver
}

// nodeMap is a mapping of node names to ENI nodes
type nodeMap map[string]*Node

// NodeManager manages all nodes with ENIs
type NodeManager struct {
	mutex            lock.RWMutex
	nodes            nodeMap
	instancesAPI     AllocationImplementation
	k8sAPI           k8sImplementation
	metricsAPI       metricsAPI
	resyncTrigger    *trigger.Trigger
	parallelWorkers  int64
	releaseExcessIPs bool
}

// NewNodeManager returns a new NodeManager
func NewNodeManager(instancesAPI AllocationImplementation, k8sAPI k8sImplementation, metrics metricsAPI, parallelWorkers int64, releaseExcessIPs bool) (*NodeManager, error) {
	if parallelWorkers < 1 {
		parallelWorkers = 1
	}

	mngr := &NodeManager{
		nodes:            nodeMap{},
		instancesAPI:     instancesAPI,
		k8sAPI:           k8sAPI,
		metricsAPI:       metrics,
		parallelWorkers:  parallelWorkers,
		releaseExcessIPs: releaseExcessIPs,
	}

	resyncTrigger, err := trigger.NewTrigger(trigger.Parameters{
		Name:            "ipam-node-manager-resync",
		MinInterval:     10 * time.Millisecond,
		MetricsObserver: metrics.ResyncTrigger(),
		TriggerFunc: func(reasons []string) {
			syncTime := instancesAPI.Resync(context.TODO())
			mngr.Resync(context.TODO(), syncTime)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to initialize resync trigger: %s", err)
	}

	mngr.resyncTrigger = resyncTrigger

	return mngr, nil
}

// GetNames returns the list of all node names
func (n *NodeManager) GetNames() (allNodeNames []string) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	allNodeNames = make([]string, 0, len(n.nodes))

	for name := range n.nodes {
		allNodeNames = append(allNodeNames, name)
	}

	return
}

// Update is called whenever a CiliumNode resource has been updated in the
// Kubernetes apiserver
func (n *NodeManager) Update(resource *v2.CiliumNode) bool {
	n.mutex.Lock()
	node, ok := n.nodes[resource.Name]
	if !ok {
		node = &Node{
			name:    resource.Name,
			manager: n,
		}

		node.ops = n.instancesAPI.CreateNode(resource, node)

		poolMaintainer, err := trigger.NewTrigger(trigger.Parameters{
			Name:            fmt.Sprintf("ipam-pool-maintainer-%s", resource.Name),
			MinInterval:     10 * time.Millisecond,
			MetricsObserver: n.metricsAPI.PoolMaintainerTrigger(),
			TriggerFunc: func(reasons []string) {
				if err := node.MaintainIPPool(context.TODO()); err != nil {
					node.logger().WithError(err).Warning("Unable to maintain ip pool of node")
				}
			},
		})
		if err != nil {
			node.logger().WithError(err).Error("Unable to create pool-maintainer trigger")
			return false
		}

		k8sSync, err := trigger.NewTrigger(trigger.Parameters{
			Name:            fmt.Sprintf("ipam-node-k8s-sync-%s", resource.Name),
			MinInterval:     10 * time.Millisecond,
			MetricsObserver: n.metricsAPI.K8sSyncTrigger(),
			TriggerFunc: func(reasons []string) {
				node.syncToAPIServer()
			},
		})
		if err != nil {
			poolMaintainer.Shutdown()
			node.logger().WithError(err).Error("Unable to create k8s-sync trigger")
			return false
		}

		node.poolMaintainer = poolMaintainer
		node.k8sSync = k8sSync
		n.nodes[node.name] = node

		log.WithField(fieldName, resource.Name).Info("Discovered new CiliumNode custom resource")
	}
	n.mutex.Unlock()

	return node.UpdatedResource(resource)
}

// Delete is called after a CiliumNode resource has been deleted via the
// Kubernetes apiserver
func (n *NodeManager) Delete(nodeName string) {
	n.mutex.Lock()
	if node, ok := n.nodes[nodeName]; ok {
		if node.poolMaintainer != nil {
			node.poolMaintainer.Shutdown()
		}
		if node.k8sSync != nil {
			node.k8sSync.Shutdown()
		}
	}

	delete(n.nodes, nodeName)
	n.mutex.Unlock()
}

// Get returns the node with the given name
func (n *NodeManager) Get(nodeName string) *Node {
	n.mutex.RLock()
	node := n.nodes[nodeName]
	n.mutex.RUnlock()
	return node
}

// GetNodesByIPWatermark returns all nodes that require addresses to be
// allocated or released, sorted by the number of addresses needed to be operated
// in descending order. Number of addresses to be released is negative value
// so that nodes with IP deficit are resolved first
func (n *NodeManager) GetNodesByIPWatermark() []*Node {
	n.mutex.RLock()
	list := make([]*Node, len(n.nodes))
	index := 0
	for _, node := range n.nodes {
		list[index] = node
		index++
	}
	n.mutex.RUnlock()

	sort.Slice(list, func(i, j int) bool {
		valuei := list[i].GetNeededAddresses()
		valuej := list[j].GetNeededAddresses()
		// Number of addresses to be released is negative value,
		// nodes with more excess addresses are released earlier
		if valuei < 0 && valuej < 0 {
			return valuei < valuej
		}
		return valuei > valuej
	})

	return list
}

type resyncStats struct {
	mutex               lock.Mutex
	totalUsed           int
	totalAvailable      int
	totalNeeded         int
	remainingInterfaces int
	nodes               int
	nodesAtCapacity     int
	nodesInDeficit      int
}

func (n *NodeManager) resyncNode(ctx context.Context, node *Node, stats *resyncStats, syncTime time.Time) {
	node.mutex.Lock()

	if syncTime.After(node.resyncNeeded) {
		node.loggerLocked().Debug("Resetting resyncNeeded")
		node.resyncNeeded = time.Time{}
	}

	node.recalculateLocked()
	allocationNeeded := node.allocationNeeded()
	releaseNeeded := node.releaseNeeded()
	if allocationNeeded || releaseNeeded {
		node.waitingForPoolMaintenance = true
		node.poolMaintainer.Trigger()
	}

	stats.mutex.Lock()
	stats.totalUsed += node.stats.UsedIPs
	availableOnNode := node.stats.AvailableIPs - node.stats.UsedIPs
	stats.totalAvailable += availableOnNode
	stats.totalNeeded += node.stats.NeededIPs
	stats.remainingInterfaces += node.stats.RemainingInterfaces
	stats.nodes++

	if allocationNeeded {
		stats.nodesInDeficit++
	}

	if node.stats.RemainingInterfaces == 0 && availableOnNode == 0 {
		stats.nodesAtCapacity++
	}

	stats.mutex.Unlock()
	node.mutex.Unlock()

	node.k8sSync.Trigger()
}

// Resync will attend all nodes and resolves IP deficits. The order of
// attendance is defined by the number of IPs needed to reach the configured
// watermarks. Any updates to the node resource are synchronized to the
// Kubernetes apiserver.
func (n *NodeManager) Resync(ctx context.Context, syncTime time.Time) {
	n.metricsAPI.IncResyncCount()

	stats := resyncStats{}
	sem := semaphore.NewWeighted(n.parallelWorkers)

	for _, node := range n.GetNodesByIPWatermark() {
		err := sem.Acquire(ctx, 1)
		if err != nil {
			continue
		}
		go func(node *Node, stats *resyncStats) {
			n.resyncNode(ctx, node, stats, syncTime)
			sem.Release(1)
		}(node, &stats)
	}

	// Acquire the full semaphore, this requires all go routines to
	// complete and thus blocks until all nodes are synced
	sem.Acquire(ctx, n.parallelWorkers)

	n.metricsAPI.SetAllocatedIPs("used", stats.totalUsed)
	n.metricsAPI.SetAllocatedIPs("available", stats.totalAvailable)
	n.metricsAPI.SetAllocatedIPs("needed", stats.totalNeeded)
	n.metricsAPI.SetAvailableENIs(stats.remainingInterfaces)
	n.metricsAPI.SetNodes("total", stats.nodes)
	n.metricsAPI.SetNodes("in-deficit", stats.nodesInDeficit)
	n.metricsAPI.SetNodes("at-capacity", stats.nodesAtCapacity)

	for poolID, quota := range n.instancesAPI.GetPoolQuota() {
		n.metricsAPI.SetAvailableIPsPerSubnet(string(poolID), quota.AvailabilityZone, quota.AvailableIPs)
	}
}
