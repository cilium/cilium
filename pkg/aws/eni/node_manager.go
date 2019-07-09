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

	"github.com/sirupsen/logrus"
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
	FindSubnetByTags(vpcID, availabilityZone string, required types.Tags) *types.Subnet
	Resync()
}

type ec2API interface {
	CreateNetworkInterface(toAllocate int64, subnetID, desc string, groups []string) (string, error)
	DeleteNetworkInterface(eniID string) error
	AttachNetworkInterface(index int64, instanceID, eniID string) (string, error)
	ModifyNetworkInterface(eniID, attachmentID string, deleteOnTermination bool) error
	AssignPrivateIpAddresses(eniID string, addresses int64) error
}

type metricsAPI interface {
	IncENIAllocationAttempt(status, subnetID string)
	AddIPAllocation(subnetID string, allocated int64)
	SetAllocatedIPs(typ string, allocated int)
	SetAvailableENIs(available int)
	SetNodes(category string, nodes int)
	IncResyncCount()
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
	deficitResolver *trigger.Trigger
	parallelWorkers int64
}

// NewNodeManager returns a new NodeManager
func NewNodeManager(instancesAPI nodeManagerAPI, ec2API ec2API, k8sAPI k8sAPI, metrics metricsAPI, parallelWorkers int64) (*NodeManager, error) {
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
	}

	deficitResolver, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "eni-node-manager-deficit-resolver",
		MinInterval: 10 * time.Millisecond,
		TriggerFunc: func(reasons []string) {
			sem := semaphore.NewWeighted(parallelWorkers)

			for _, name := range reasons {
				sem.Acquire(context.TODO(), 1)
				go func(name string) {
					if node := mngr.Get(name); node != nil {
						if err := node.ResolveIPDeficit(); err != nil {
							node.logger().WithError(err).Warning("Unable to resolve IP deficit of node")
						}
					} else {
						log.WithField(fieldName, name).Warning("Node has disappeared while allocation request was queued")
					}
					sem.Release(1)
				}(name)
			}
			// Acquire the full semaphore, this requires all go routines to
			// complete and thus blocks until all nodes are synced
			sem.Acquire(context.TODO(), parallelWorkers)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to initialize deficit resolver trigger: %s", err)
	}

	resyncTrigger, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "eni-node-manager-resync",
		MinInterval: 10 * time.Millisecond,
		TriggerFunc: func(reasons []string) {
			instancesAPI.Resync()
			mngr.Resync()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to initialize resync trigger: %s", err)
	}

	mngr.resyncTrigger = resyncTrigger
	mngr.deficitResolver = deficitResolver

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

// GetNodesByNeededAddresses returns all nodes that require addresses to be
// allocated, sorted by the number of addresses needed in descending order
func (n *NodeManager) GetNodesByNeededAddresses() []*Node {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	list := make([]*Node, len(n.nodes))
	index := 0
	for _, node := range n.nodes {
		list[index] = node
		index++
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].getNeededAddresses() > list[j].getNeededAddresses()
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

func (n *NodeManager) resyncNode(node *Node, stats *resyncStats) {
	node.mutex.Lock()

	// Resync() is always called after resync of the instance data,
	// mark node as resynced
	node.resyncNeeded = false
	allocationNeeded := node.recalculateLocked()
	node.loggerLocked().WithFields(logrus.Fields{
		fieldName:   node.name,
		"available": node.stats.availableIPs,
		"used":      node.stats.usedIPs,
	}).Debug("Recalculated allocation requirements")

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
	stats.mutex.Unlock()

	if allocationNeeded && node.stats.remainingInterfaces > 0 {
		n.deficitResolver.TriggerWithReason(node.name)
	}
	node.mutex.Unlock()

	node.SyncToAPIServer()
}

// Resync will attend all nodes and resolves IP deficits. The order of
// attendance is defined by the number of IPs needed to reach the configured
// watermarks. Any updates to the node resource are synchronized to the
// Kubernetes apiserver.
func (n *NodeManager) Resync() {
	stats := resyncStats{}
	sem := semaphore.NewWeighted(n.parallelWorkers)

	for _, node := range n.GetNodesByNeededAddresses() {
		sem.Acquire(context.TODO(), 1)
		go func(node *Node, stats *resyncStats) {
			n.resyncNode(node, stats)
			sem.Release(1)
		}(node, &stats)
	}

	// Acquire the full semaphore, this requires all go routines to
	// complete and thus blocks until all nodes are synced
	sem.Acquire(context.TODO(), n.parallelWorkers)

	n.metricsAPI.SetAllocatedIPs("used", stats.totalUsed)
	n.metricsAPI.SetAllocatedIPs("available", stats.totalAvailable)
	n.metricsAPI.SetAllocatedIPs("needed", stats.totalNeeded)
	n.metricsAPI.SetAvailableENIs(stats.remainingInterfaces)
	n.metricsAPI.SetNodes("total", stats.nodes)
	n.metricsAPI.SetNodes("in-deficit", stats.nodesInDeficit)
	n.metricsAPI.SetNodes("at-capacity", stats.nodesAtCapacity)
}
