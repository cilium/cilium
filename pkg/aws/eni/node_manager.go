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
	"sort"
	"time"

	"github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/trigger"

	"golang.org/x/sync/semaphore"
)

type k8sAPI interface {
	Update(origResource, newResource *v2.CiliumNode) (*v2.CiliumNode, error)
	UpdateStatus(origResource, newResource *v2.CiliumNode) (*v2.CiliumNode, error)
	Get(name string) (*v2.CiliumNode, error)
}

type nodeManagerAPI interface {
	GetENI(instanceID string, index int) *v2.ENI
	GetENIs(instanceID string) []*v2.ENI
	GetSubnet(subnetID string) *types.Subnet
	GetSubnets(ctx context.Context) types.SubnetMap
	FindSubnetByTags(vpcID, availabilityZone string, required types.Tags) *types.Subnet
	FindSecurityGroupByTags(vpcID string, required types.Tags) []*types.SecurityGroup
	Resync(ctx context.Context) time.Time
	UpdateENI(instanceID string, eni *v2.ENI)
}

type ec2API interface {
	CreateNetworkInterface(ctx context.Context, toAllocate int64, subnetID, desc string, groups []string) (string, *v2.ENI, error)
	DeleteNetworkInterface(ctx context.Context, eniID string) error
	AttachNetworkInterface(ctx context.Context, index int64, instanceID, eniID string) (string, error)
	ModifyNetworkInterface(ctx context.Context, eniID, attachmentID string, deleteOnTermination bool) error
	AssignPrivateIpAddresses(ctx context.Context, eniID string, addresses int64) error
	UnassignPrivateIpAddresses(ctx context.Context, eniID string, addresses []string) error
	TagENI(ctx context.Context, eniID string, eniTags map[string]string) error
}

type metricsAPI interface {
	IncENIAllocationAttempt(status, subnetID string)
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
	mutex           lock.RWMutex
	nodes           nodeMap
	instancesAPI    nodeManagerAPI
	ec2API          ec2API
	k8sAPI          k8sAPI
	metricsAPI      metricsAPI
	resyncTrigger   *trigger.Trigger
	parallelWorkers int64
	eniTags         map[string]string
}

// NewNodeManager returns a new NodeManager
func NewNodeManager(instancesAPI nodeManagerAPI, ec2API ec2API, k8sAPI k8sAPI, metrics metricsAPI, parallelWorkers int64, eniTags map[string]string) (*NodeManager, error) {
	if parallelWorkers < 1 {
		parallelWorkers = 1
	}

	mngr := &NodeManager{
		nodes:           nodeMap{},
		instancesAPI:    instancesAPI,
		ec2API:          ec2API,
		k8sAPI:          k8sAPI,
		metricsAPI:      metrics,
		parallelWorkers: parallelWorkers,
		eniTags:         eniTags,
	}

	resyncTrigger, err := trigger.NewTrigger(trigger.Parameters{
		Name:            "eni-node-manager-resync",
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

		poolMaintainer, err := trigger.NewTrigger(trigger.Parameters{
			Name:            fmt.Sprintf("eni-pool-maintainer-%s", resource.Name),
			MinInterval:     10 * time.Millisecond,
			MetricsObserver: n.metricsAPI.PoolMaintainerTrigger(),
			TriggerFunc: func(reasons []string) {
				if err := node.MaintainIpPool(context.TODO()); err != nil {
					node.logger().WithError(err).Warning("Unable to maintain ip pool of node")
				}
			},
		})
		if err != nil {
			node.logger().WithError(err).Error("Unable to create pool-maintainer trigger")
			return false
		}

		k8sSync, err := trigger.NewTrigger(trigger.Parameters{
			Name:            fmt.Sprintf("eni-node-k8s-sync-%s", resource.Name),
			MinInterval:     10 * time.Millisecond,
			MetricsObserver: n.metricsAPI.K8sSyncTrigger(),
			TriggerFunc: func(reasons []string) {
				node.SyncToAPIServer()
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

	return node.updatedResource(resource)
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
		valuei := list[i].getNeededAddresses()
		valuej := list[j].getNeededAddresses()
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
	stats.totalUsed += node.stats.usedIPs
	availableOnNode := node.stats.availableIPs - node.stats.usedIPs
	stats.totalAvailable += availableOnNode
	stats.totalNeeded += node.stats.neededIPs
	stats.remainingInterfaces += node.stats.remainingInterfaces
	stats.nodes++

	if allocationNeeded {
		stats.nodesInDeficit++
	}

	if node.stats.remainingInterfaces == 0 && availableOnNode == 0 {
		stats.nodesAtCapacity++
	}

	for subnetID, subnet := range n.instancesAPI.GetSubnets(ctx) {
		n.metricsAPI.SetAvailableIPsPerSubnet(subnetID, subnet.AvailabilityZone, subnet.AvailableAddresses)
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
}
