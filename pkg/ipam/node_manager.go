// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2017 Lyft, Inc.

package ipam

import (
	"context"
	"fmt"
	"sort"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/controller"
	ipamStats "github.com/cilium/cilium/pkg/ipam/stats"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

var ipamNodeIntervalControllerGroup = controller.NewGroup("ipam-node-interval-refresh")

// CiliumNodeGetterUpdater defines the interface used to interact with the k8s
// apiserver to retrieve and update the CiliumNode custom resource
type CiliumNodeGetterUpdater interface {
	Create(node *v2.CiliumNode) (*v2.CiliumNode, error)
	Update(origResource, newResource *v2.CiliumNode) (*v2.CiliumNode, error)
	UpdateStatus(origResource, newResource *v2.CiliumNode) (*v2.CiliumNode, error)
	Get(name string) (*v2.CiliumNode, error)
}

// NodeOperations is the interface an IPAM implementation must provide in order
// to provide IP allocation for a node. The structure implementing this API
// *must* be aware of the node connected to this implementation. This is
// achieved by considering the node context provided in
// AllocationImplementation.CreateNode() function and returning a
// NodeOperations implementation which performs operations in the context of
// that node.
type NodeOperations interface {
	// UpdateNode is called when an update to the CiliumNode is received.
	UpdatedNode(obj *v2.CiliumNode)

	// PopulateStatusFields is called to give the implementation a chance
	// to populate any implementation specific fields in CiliumNode.Status.
	PopulateStatusFields(resource *v2.CiliumNode)

	// CreateInterface is called to create a new interface. This is only
	// done if PrepareIPAllocation indicates that no more IPv4 addresses are available
	// (AllocationAction.IPv4.AvailableForAllocation == 0) for allocation but
	// interfaces are available for creation
	// (AllocationAction.EmptyInterfaceSlots > 0). This function must
	// create the interface *and* allocate up to
	// AllocationAction.IPv4.MaxIPsToAllocate.
	CreateInterface(ctx context.Context, allocation *AllocationAction, scopedLog *logrus.Entry) (int, string, error)

	// CreatCreateIPv6InterfaceeInterface is called to create a new interface. This is only
	// done if PrepareIPv6Allocation indicates that no more IPv6 addresses are available
	// (AllocationAction.IPv6.AvailableForAllocation == 0) for allocation but
	// interfaces are available for creation
	// (AllocationAction.EmptyInterfaceSlots > 0). This function must
	// create the interface *and* allocate up to
	// AllocationAction.IPv6.MaxIPsToAllocate.
	CreateIPv6Interface(ctx context.Context, allocation *AllocationAction, scopedLog *logrus.Entry) (int, string, error)

	// ResyncInterfacesAndIPs is called to synchronize the latest list of
	// interfaces and IPv4 addressses associated with the node. This function is called
	// sparingly as this information is kept in sync based on the success
	// of the functions AllocateIPs(), ReleaseIPs() and CreateInterface().
	// It returns all available ip in node and remaining available interfaces
	// that can either be allocated or have not yet exhausted the instance specific quota of addresses
	// and error occurred during execution.
	ResyncInterfacesAndIPs(ctx context.Context, scopedLog *logrus.Entry) (ipamTypes.AllocationMap, ipamStats.InterfaceStats, error)

	// ResyncInterfacesAndIPs is called to synchronize the latest list of
	// interfaces and IPv6 addresses associated with the node. This function is called
	// sparingly as this information is kept in sync based on the success
	// of the functions AllocateIPs(), ReleaseIPs() and CreateInterface().
	// It returns all available ip in node and remaining available interfaces
	// that can either be allocated or have not yet exhausted the instance specific quota of addresses
	// and error occurred during execution.
	ResyncInterfacesAndIPv6s(ctx context.Context, scopedLog *logrus.Entry) (ipamTypes.AllocationMap, ipamStats.InterfaceStats, error)

	// PrepareIPAllocation is called to calculate the number of IPs that
	// can be allocated on the node and whether a new network interface
	// must be attached to the node.
	PrepareIPAllocation(scopedLog *logrus.Entry) (*AllocationAction, error)

	// PrepareIPv6Allocation is called to calculate the number of IPv6 addresses that
	// can be allocated on the node and whether a new network interface
	// must be attached to the node.
	PrepareIPv6Allocation(scopedLog *logrus.Entry) (*AllocationAction, error)

	// AllocateIPs is called after invoking PrepareIPAllocation and needs
	// to perform the actual IPv4 allocation.
	AllocateIPs(ctx context.Context, allocation *AllocationAction) error

	// AllocateIPv6s is called after invoking PrepareIPv6Allocation and needs
	// to perform the actual IPv6 allocation.
	AllocateIPv6s(ctx context.Context, allocation *AllocationAction) error

	// PrepareIPRelease is called to calculate whether any IP excess needs
	// to be resolved. It behaves identical to PrepareIPAllocation but
	// indicates a need to release IPs.
	PrepareIPRelease(excessIPs int, scopedLog *logrus.Entry) *ReleaseAction

	// PrepareIPv6Release is called to calculate whether any IPv6 excess needs
	// to be resolved. It behaves identical to PrepareIPv6Allocation but
	// indicates a need to release IPv6 addresses.
	PrepareIPv6Release(excessIPs int, scopedLog *logrus.Entry) *ReleaseAction

	// ReleaseIPs is called after invoking PrepareIPRelease and needs to
	// perform the release of IPs.
	ReleaseIPs(ctx context.Context, release *ReleaseAction) error

	// GetMaximumAllocatableIPv4 returns the maximum amount of IPv4 addresses
	// that can be allocated to the instance
	GetMaximumAllocatableIPv4() int

	// GetMaximumAllocatableIPv6 returns the maximum amount of IPv6 addresses
	// that can be allocated to the instance
	GetMaximumAllocatableIPv6() int

	// GetMinimumAllocatableIPv4 returns the minimum amount of IPv4 addresses that
	// must be allocated to the instance.
	GetMinimumAllocatableIPv4() int

	// GetMinimumAllocatableIPv6 returns the minimum amount of IPv6 addresses that
	// must be allocated to the instance.
	GetMinimumAllocatableIPv6() int

	// IsPrefixDelegated helps identify if a node supports IPv4 prefix delegation
	IsPrefixDelegated() bool

	// IsIPv6PrefixDelegated helps identify if a node supports IPv6 prefix delegation
	IsIPv6PrefixDelegated() bool

	// GetUsedIPWithPrefixes returns the total number of used IPv4 addressess including
	// all IPs in a prefix if at-least one of the prefix IPs is in use.
	GetUsedIPWithPrefixes() int

	// GetUsedIPv6WithPrefixes returns the total number of used IPv6 addressess including
	// all IPs in a prefix if at-least one of the prefix IPs is in use.
	GetUsedIPv6WithPrefixes() int
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

	// GetPoolQuota is called to retrieve the remaining IPv4 addresses in all
	// IP pools known to the IPAM implementation.
	GetPoolQuota() ipamTypes.PoolQuotaMap

	// Resync is called periodically to give the IPAM implementation a
	// chance to resync its own state with external APIs or systems. It is
	// also called when the IPAM layer detects that state got out of sync.
	Resync(ctx context.Context) time.Time

	// InstanceSync is called to sync the state of the specified instance with
	// external APIs or systems.
	InstanceSync(ctx context.Context, instanceID string) time.Time

	// HasInstance returns whether the instance is in instances
	HasInstance(instanceID string) bool

	// DeleteInstance deletes the instance from instances
	DeleteInstance(instanceID string)
}

// MetricsAPI represents the metrics being maintained by a NodeManager
type MetricsAPI interface {
	MetricsNodeAPI

	AllocationAttempt(typ, status, subnetID string, observe float64)
	ReleaseAttempt(typ, status, subnetID string, observe float64)
	IncInterfaceAllocation(subnetID string)
	AddIPAllocation(subnetID string, allocated int64)
	AddIPRelease(subnetID string, released int64)
	SetAllocatedIPs(typ string, allocated int)
	SetAvailableInterfaces(available int)
	SetInterfaceCandidates(interfaceCandidates int)
	SetEmptyInterfaceSlots(emptyInterfaceSlots int)
	SetAvailableIPsPerSubnet(subnetID string, availabilityZone string, ipv4Available int)
	SetAvailableIPv6sPerSubnet(subnetID string, availabilityZone string, ipv6Available int)
	SetNodes(category string, nodes int)
	IncResyncCount()
	IPv6PoolMaintainerTrigger() trigger.MetricsObserver
	PoolMaintainerTrigger() trigger.MetricsObserver
	K8sSyncTrigger() trigger.MetricsObserver
	ResyncTrigger() trigger.MetricsObserver
}

type MetricsNodeAPI interface {
	SetIPAvailable(node string, cap int)
	SetIPUsed(node string, used int)
	SetIPNeeded(node string, needed int)
	DeleteNode(node string)
}

// nodeMap is a mapping of node names to ENI nodes
type nodeMap map[string]*Node

type NodeManager struct {
	mutex                lock.RWMutex
	nodes                nodeMap
	instancesAPI         AllocationImplementation
	k8sAPI               CiliumNodeGetterUpdater
	metricsAPI           MetricsAPI
	parallelWorkers      int64
	releaseExcessIPs     bool
	stableInstancesAPI   bool
	prefixDelegation     bool
	ipv6PrefixDelegation bool
}

func (n *NodeManager) ClusterSizeDependantInterval(baseInterval time.Duration) time.Duration {
	n.mutex.RLock()
	numNodes := len(n.nodes)
	n.mutex.RUnlock()

	return backoff.ClusterSizeDependantInterval(baseInterval, numNodes)
}

// NewNodeManager returns a new NodeManager
func NewNodeManager(instancesAPI AllocationImplementation, k8sAPI CiliumNodeGetterUpdater, metrics MetricsAPI,
	parallelWorkers int64, releaseExcessIPs bool, prefixDelegation, ipv6prefixDelegation bool) (*NodeManager, error) {
	if parallelWorkers < 1 {
		parallelWorkers = 1
	}

	mngr := &NodeManager{
		nodes:                nodeMap{},
		instancesAPI:         instancesAPI,
		k8sAPI:               k8sAPI,
		metricsAPI:           metrics,
		parallelWorkers:      parallelWorkers,
		releaseExcessIPs:     releaseExcessIPs,
		prefixDelegation:     prefixDelegation,
		ipv6PrefixDelegation: ipv6prefixDelegation,
	}

	// Assume readiness, the initial blocking resync in Start() will update
	// the readiness
	mngr.SetInstancesAPIReadiness(true)

	return mngr, nil
}

func (n *NodeManager) instancesAPIResync(ctx context.Context) (time.Time, bool) {
	syncTime := n.instancesAPI.Resync(ctx)
	success := !syncTime.IsZero()
	n.SetInstancesAPIReadiness(success)
	return syncTime, success
}

// Start kicks of the NodeManager by performing the initial state
// synchronization and starting the background sync goroutine
func (n *NodeManager) Start(ctx context.Context) error {
	// Trigger the initial resync in a blocking manner
	if _, ok := n.instancesAPIResync(ctx); !ok {
		return fmt.Errorf("Initial synchronization with instances API failed")
	}

	// Start an interval based  background resync for safety, it will
	// synchronize the state regularly and resolve eventual deficit if the
	// event driven trigger fails, and also release excess IP addresses
	// if release-excess-ips is enabled
	go func() {
		mngr := controller.NewManager()
		mngr.UpdateController("ipam-node-interval-refresh",
			controller.ControllerParams{
				Group:       ipamNodeIntervalControllerGroup,
				RunInterval: time.Minute,
				DoFunc: func(ctx context.Context) error {
					if syncTime, ok := n.instancesAPIResync(ctx); ok {
						n.Resync(ctx, syncTime)
					}
					return nil
				},
			})
	}()

	return nil
}

// SetInstancesAPIReadiness sets the readiness state of the instances API
func (n *NodeManager) SetInstancesAPIReadiness(ready bool) {
	n.mutex.Lock()
	n.stableInstancesAPI = ready
	n.mutex.Unlock()
}

// InstancesAPIIsReady returns true if the instances API is stable and ready
func (n *NodeManager) InstancesAPIIsReady() bool {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return n.stableInstancesAPI
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

// Upsert is called whenever a CiliumNode resource has been updated in the
// Kubernetes apiserver. The CiliumNode will be created if it didn't exist before.
func (n *NodeManager) Upsert(resource *v2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	node, ok := n.nodes[resource.Name]
	if !ok {
		node = &Node{
			name:       resource.Name,
			manager:    n,
			logLimiter: logging.NewLimiter(10*time.Second, 3), // 1 log / 10 secs, burst of 3
			ipv4Alloc: ipAllocAttrs{
				ipsMarkedForRelease: make(map[string]time.Time),
				ipReleaseStatus:     make(map[string]string),
			},
		}

		if n.ipv6PrefixDelegation {
			node.ipv6Alloc = ipAllocAttrs{
				ipsMarkedForRelease: make(map[string]time.Time),
				ipReleaseStatus:     make(map[string]string),
			}
		}

		ctx, cancel := context.WithCancel(context.Background())
		// InstanceAPI is stale and the instances API is stable then do resync instancesAPI to sync instances
		if !n.instancesAPI.HasInstance(resource.InstanceID()) && n.stableInstancesAPI {
			if syncTime := n.instancesAPI.InstanceSync(ctx, resource.InstanceID()); syncTime.IsZero() {
				node.logger().Warning("Failed to resync the instance from the API after new node was found")
				n.stableInstancesAPI = false
			} else {
				n.stableInstancesAPI = true
			}
		}

		node.ops = n.instancesAPI.CreateNode(resource, node)

		backoff := &backoff.Exponential{
			Max:         5 * time.Minute,
			Jitter:      true,
			NodeManager: n,
			Name:        fmt.Sprintf("ipam-pool-maintainer-%s", resource.Name),
			ResetAfter:  10 * time.Minute,
		}
		poolMaintainer, err := trigger.NewTrigger(trigger.Parameters{
			Name:            fmt.Sprintf("ipam-pool-maintainer-%s", resource.Name),
			MinInterval:     10 * time.Millisecond,
			MetricsObserver: n.metricsAPI.PoolMaintainerTrigger(),
			TriggerFunc: func(reasons []string) {
				if err := node.MaintainIPPool(ctx); err != nil {
					node.logger().WithError(err).Warning("Unable to maintain ip pool of node")
					backoff.Wait(ctx)
				}
			},
			ShutdownFunc: cancel,
		})
		if err != nil {
			node.logger().WithError(err).Error("Unable to create pool-maintainer trigger")
			return
		}

		ipv6PoolMaintainer := new(trigger.Trigger)
		if n.ipv6PrefixDelegation {
			ipv6PoolMaintainer, err = trigger.NewTrigger(trigger.Parameters{
				Name:            fmt.Sprintf("ipam-ipv6-pool-maintainer-%s", resource.Name),
				MinInterval:     10 * time.Millisecond,
				MetricsObserver: n.metricsAPI.IPv6PoolMaintainerTrigger(),
				TriggerFunc: func(reasons []string) {
					if err := node.MaintainIPv6Pool(ctx); err != nil {
						node.logger().WithError(err).Warning("Unable to maintain ipv6 pools of node")
						backoff.Wait(ctx)
					}
				},
				ShutdownFunc: cancel,
			})
			if err != nil {
				node.logger().WithError(err).Error("Unable to create ipv6-pool-maintainer trigger")
				return
			}

			v6Retry, err := trigger.NewTrigger(trigger.Parameters{
				Name:        fmt.Sprintf("ipam-ipv6-pool-maintainer-%s-retry", resource.Name),
				MinInterval: time.Minute, // large minimal interval to not retry too often
				TriggerFunc: func(reasons []string) { ipv6PoolMaintainer.Trigger() },
			})
			if err != nil {
				node.logger().WithError(err).Error("Unable to create ipv6-pool-maintainer-retry trigger")
				return
			}
			node.ipv6Retry = v6Retry
		}

		retry, err := trigger.NewTrigger(trigger.Parameters{
			Name:        fmt.Sprintf("ipam-pool-maintainer-%s-retry", resource.Name),
			MinInterval: time.Minute, // large minimal interval to not retry too often
			TriggerFunc: func(reasons []string) { poolMaintainer.Trigger() },
		})
		if err != nil {
			node.logger().WithError(err).Error("Unable to create pool-maintainer-retry trigger")
			return
		}
		node.retry = retry

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
			if n.ipv6PrefixDelegation {
				ipv6PoolMaintainer.Shutdown()
			}
			node.logger().WithError(err).Error("Unable to create k8s-sync trigger")
			return
		}

		instanceSync, err := trigger.NewTrigger(trigger.Parameters{
			Name:            fmt.Sprintf("ipam-node-instance-sync-%s", resource.Name),
			MinInterval:     10 * time.Millisecond,
			MetricsObserver: n.metricsAPI.ResyncTrigger(),
			TriggerFunc: func(reasons []string) {
				if syncTime, ok := node.instanceAPISync(ctx, resource.InstanceID()); ok {
					node.manager.Resync(ctx, syncTime)
				}
			},
		})
		if err != nil {
			poolMaintainer.Shutdown()
			if n.ipv6PrefixDelegation {
				ipv6PoolMaintainer.Shutdown()
			}
			k8sSync.Shutdown()
			node.logger().WithError(err).Error("Unable to create instance-sync trigger")
			return
		}
		node.instanceSync = instanceSync

		node.poolMaintainer = poolMaintainer
		if n.ipv6PrefixDelegation {
			node.ipv6PoolMaintainer = ipv6PoolMaintainer
		}
		node.k8sSync = k8sSync
		n.nodes[node.name] = node
		log.WithField(fieldName, resource.Name).Info("Discovered new CiliumNode custom resource")
	}
	// Update the resource in the node while holding the lock, otherwise resyncs can be
	// triggered prior to the update being applied.
	node.UpdatedResource(resource)
}

// Delete is called after a CiliumNode resource has been deleted via the
// Kubernetes apiserver
func (n *NodeManager) Delete(resource *v2.CiliumNode) {
	n.mutex.Lock()

	if node, ok := n.nodes[resource.Name]; ok {
		// Stop target_node metrics related to this node being emitted.
		n.metricsAPI.DeleteNode(node.name)

		if node.poolMaintainer != nil {
			node.poolMaintainer.Shutdown()
		}
		if node.k8sSync != nil {
			node.k8sSync.Shutdown()
		}
		if node.retry != nil {
			node.retry.Shutdown()
		}
		if node.instanceSync != nil {
			node.instanceSync.Shutdown()
		}
	}

	// Delete the instance from instanceManager. This will cause Update() to
	// invoke instancesAPIResync if this instance rejoins the cluster.
	// This ensures that Node.recalculate() does not use stale data for
	// instances which rejoin the cluster after their EC2 configuration has changed.
	if resource.Spec.InstanceID != "" {
		n.instancesAPI.DeleteInstance(resource.Spec.InstanceID)
	}

	delete(n.nodes, resource.Name)
	n.mutex.Unlock()
}

// Get returns the node with the given name
func (n *NodeManager) Get(nodeName string) *Node {
	n.mutex.RLock()
	node := n.nodes[nodeName]
	n.mutex.RUnlock()
	return node
}

// GetNodesByIPWatermarkLocked returns all nodes that require IPv4 addresses to be
// allocated or released, sorted by the number of addresses needed to be operated
// in descending order. Number of addresses to be released is negative value
// so that nodes with IP deficit are resolved first
// The caller must hold the NodeManager lock
func (n *NodeManager) GetNodesByIPWatermarkLocked() []*Node {
	list := make([]*Node, len(n.nodes))
	index := 0
	for _, node := range n.nodes {
		list[index] = node
		index++
	}

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

// GetNodesByIPv6WatermarkLocked returns all nodes that require IPv6 addresses to
// be allocated or released, sorted by the number of addresses needed to be operated
// in descending order. Number of addresses to be released is negative value
// so that nodes with IP deficit are resolved first
// The caller must hold the NodeManager lock
func (n *NodeManager) GetNodesByIPv6WatermarkLocked() []*Node {
	list := make([]*Node, len(n.nodes))
	index := 0
	for _, node := range n.nodes {
		list[index] = node
		index++
	}

	sort.Slice(list, func(i, j int) bool {
		valuei := list[i].GetNeededIPv6Addresses()
		valuej := list[j].GetNeededIPv6Addresses()
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
	ipv4                ipResyncStats
	ipv6                ipResyncStats
	emptyInterfaceSlots int
}

type ipResyncStats struct {
	totalUsed           int
	totalAvailable      int
	totalNeeded         int
	remainingInterfaces int
	interfaceCandidates int
	nodes               int
	nodesAtCapacity     int
	nodesInDeficit      int
	nodeCapacity        int
}

func (n *NodeManager) resyncNode(ctx context.Context, node *Node, stats *resyncStats, syncTime time.Time) {
	node.updateLastResync(syncTime)
	node.recalculate()
	allocationNeeded := node.allocationNeeded()
	releaseNeeded := node.releaseNeeded()
	if allocationNeeded || releaseNeeded {
		node.requirePoolMaintenance()
		node.poolMaintainer.Trigger()
	}

	nodeStats := node.Stats()

	stats.mutex.Lock()
	stats.ipv4.totalUsed += nodeStats.IPv4.UsedIPs
	// availableOnNode is the number of available IPs on the node at this
	// current moment. It does not take into account the number of IPs that
	// can be allocated in the future.
	availableOnNode := nodeStats.IPv4.AvailableIPs - nodeStats.IPv4.UsedIPs
	stats.ipv4.totalAvailable += availableOnNode
	stats.ipv4.totalNeeded += nodeStats.IPv4.NeededIPs
	stats.ipv4.remainingInterfaces += nodeStats.IPv4.RemainingInterfaces
	stats.ipv4.interfaceCandidates += nodeStats.IPv4.InterfaceCandidates
	stats.emptyInterfaceSlots += nodeStats.EmptyInterfaceSlots
	stats.ipv4.nodes++

	stats.ipv4.nodeCapacity = nodeStats.IPv4.Capacity

	// Set per Node metrics.
	n.metricsAPI.SetIPAvailable(node.name, nodeStats.IPv4.Capacity)
	n.metricsAPI.SetIPUsed(node.name, nodeStats.IPv4.UsedIPs)
	n.metricsAPI.SetIPNeeded(node.name, nodeStats.IPv4.NeededIPs)

	if allocationNeeded {
		stats.ipv4.nodesInDeficit++
	}

	if nodeStats.IPv4.RemainingInterfaces == 0 && availableOnNode == 0 {
		stats.ipv4.nodesAtCapacity++
	}

	stats.mutex.Unlock()

	node.k8sSync.Trigger()
}

func (n *NodeManager) resyncIPv6Node(ctx context.Context, node *Node, stats *resyncStats, syncTime time.Time) {
	node.recalculateIPv6()
	allocationNeeded := node.ipv6AllocationNeeded()
	releaseNeeded := node.ipv6ReleaseNeeded()
	if allocationNeeded || releaseNeeded {
		node.requireIPv6PoolMaintenance()
		node.ipv6PoolMaintainer.Trigger()
	}

	nodeStats := node.Stats()

	stats.mutex.Lock()
	defer stats.mutex.Unlock()

	stats.ipv6.totalUsed += nodeStats.IPv6.UsedIPs
	// availableOnNode is the number of available IPs on the node at this
	// current moment. It does not take into account the number of IPs that
	// can be allocated in the future.
	availableOnNode := nodeStats.IPv6.AvailableIPs - nodeStats.IPv6.UsedIPs
	stats.ipv6.totalAvailable += availableOnNode
	stats.ipv6.totalNeeded += nodeStats.IPv6.NeededIPs
	stats.ipv6.remainingInterfaces += nodeStats.IPv6.RemainingInterfaces
	stats.ipv6.interfaceCandidates += nodeStats.IPv6.InterfaceCandidates
	//stats.emptyInterfaceSlots += nodeStats.EmptyInterfaceSlots
	stats.ipv6.nodes++

	stats.ipv6.nodeCapacity = nodeStats.IPv6.Capacity

	// Set per Node metrics.
	n.metricsAPI.SetIPAvailable(node.name, stats.ipv6.nodeCapacity)
	n.metricsAPI.SetIPUsed(node.name, nodeStats.IPv6.UsedIPs)
	n.metricsAPI.SetIPNeeded(node.name, nodeStats.IPv6.NeededIPs)

	if allocationNeeded {
		stats.ipv6.nodesInDeficit++
	}

	if nodeStats.IPv6.RemainingInterfaces == 0 && availableOnNode == 0 {
		stats.ipv6.nodesAtCapacity++
	}
}

// Resync will attend all nodes and resolves IP deficits. The order of
// attendance is defined by the number of IPs needed to reach the configured
// watermarks. Any updates to the node resource are synchronized to the
// Kubernetes apiserver.
func (n *NodeManager) Resync(ctx context.Context, syncTime time.Time) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.metricsAPI.IncResyncCount()

	stats := resyncStats{}
	sem := semaphore.NewWeighted(n.parallelWorkers)

	for _, node := range n.GetNodesByIPWatermarkLocked() {
		err := sem.Acquire(ctx, 1)
		if err != nil {
			continue
		}
		go func(node *Node, stats *resyncStats) {
			n.resyncNode(ctx, node, stats, syncTime)
			sem.Release(1)
		}(node, &stats)
	}

	if n.ipv6PrefixDelegation {
		for _, node := range n.GetNodesByIPv6WatermarkLocked() {
			err := sem.Acquire(ctx, 1)
			if err != nil {
				continue
			}
			go func(node *Node, stats *resyncStats) {
				n.resyncIPv6Node(ctx, node, stats, syncTime)
				sem.Release(1)
			}(node, &stats)
		}
	}

	// Acquire the full semaphore, this requires all goroutines to
	// complete and thus blocks until all nodes are synced
	sem.Acquire(ctx, n.parallelWorkers)

	n.metricsAPI.SetAllocatedIPs("used", stats.ipv4.totalUsed)
	n.metricsAPI.SetAllocatedIPs("available", stats.ipv4.totalAvailable)
	n.metricsAPI.SetAllocatedIPs("needed", stats.ipv4.totalNeeded)
	n.metricsAPI.SetAvailableInterfaces(stats.ipv4.remainingInterfaces)
	n.metricsAPI.SetInterfaceCandidates(stats.ipv4.interfaceCandidates)
	n.metricsAPI.SetEmptyInterfaceSlots(stats.emptyInterfaceSlots)
	n.metricsAPI.SetNodes("total", stats.ipv4.nodes)
	n.metricsAPI.SetNodes("in-deficit", stats.ipv4.nodesInDeficit)
	n.metricsAPI.SetNodes("at-capacity", stats.ipv4.nodesAtCapacity)

	// TODO Add support for IPv6 metrics

	for poolID, quota := range n.instancesAPI.GetPoolQuota() {
		n.metricsAPI.SetAvailableIPsPerSubnet(string(poolID), quota.AvailabilityZone, quota.AvailableIPs)
	}
}
