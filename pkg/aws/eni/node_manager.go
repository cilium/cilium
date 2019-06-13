// Copyright 2019 Authors of Cilium
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
	"sort"
	"time"

	"github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/trigger"
)

type k8sAPI interface {
	Update(origResource, newResource *v2.CiliumNode) (*v2.CiliumNode, error)
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
	SetNodesAtCapacity(nodes int)
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
}

// NewNodeManager returns a new NodeManager
func NewNodeManager(instancesAPI nodeManagerAPI, ec2API ec2API, k8sAPI k8sAPI, metrics metricsAPI) (*NodeManager, error) {
	mngr := &NodeManager{
		nodes:        nodeMap{},
		instancesAPI: instancesAPI,
		ec2API:       ec2API,
		k8sAPI:       k8sAPI,
		metricsAPI:   metrics,
	}

	deficitResolver, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "eni-node-manager-deficit-resolver",
		MinInterval: time.Second,
		TriggerFunc: func(reasons []string) {
			log.Infof("Executing trigger %v", reasons)
			for _, name := range reasons {
				if node := mngr.Get(name); node != nil {
					if err := node.ResolveIPDeficit(); err != nil {
						node.logger().WithError(err).Warning("Unable to resolve IP deficit of node")
					}
				} else {
					log.Warningf("Node %s seems to have disappeared while allocation request was queued", name)
				}
			}
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to initialize deficit resolver trigger: %s", err)
	}

	resyncTrigger, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "eni-node-manager-resync",
		MinInterval: time.Second,
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

		log.Infof("Discovered new CiliumNode custom resource %s", resource.Name)
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
	defer n.mutex.RUnlock()
	node := n.nodes[nodeName]
	return node
}

// byNeededIPs allows sorting of a slice of nodes by the number of addresses
// that need to be allocated
type byNeededIPs []*Node

func (a byNeededIPs) Len() int           { return len(a) }
func (a byNeededIPs) Less(i, j int) bool { return a[i].getNeededAddresses() > a[j].getNeededAddresses() }
func (a byNeededIPs) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

// GetNodesByNeededAddresses returns all nodes that require addresses to be
// allocated, sorted by the number of addresses needed in descending order
func (n *NodeManager) GetNodesByNeededAddresses() []*Node {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	list := make(byNeededIPs, len(n.nodes))
	index := 0
	for _, node := range n.nodes {
		list[index] = node
		index++
	}

	sort.Sort(list)

	return list
}

// Resync will attend all nodes and resolves IP deficits. The order of
// attendance is defined by the number of IPs needed to reach the configured
// watermarks. Any updates to the node resource are synchronized to the
// Kubernetes apiserver.
func (n *NodeManager) Resync() {
	var totalUsed, totalAvailable, totalNeeded, remainingInterfaces, nodesAtCapacity int

	for _, node := range n.GetNodesByNeededAddresses() {
		node.mutex.Lock()
		// Resync() is always called after resync of the instance data,
		// mark node as resynced
		node.resyncNeeded = false
		allocationNeeded := node.recalculateLocked()
		node.loggerLocked().Infof("Synced available=%d used=%d", node.stats.availableIPs, node.stats.usedIPs)
		totalUsed += node.stats.usedIPs
		totalAvailable += node.stats.availableIPs - node.stats.usedIPs
		totalNeeded += node.stats.neededIPs
		remainingInterfaces += node.stats.remainingInterfaces

		if remainingInterfaces == 0 && totalAvailable == 0 {
			nodesAtCapacity++
		}
		if allocationNeeded {
			node.loggerLocked().Infof("Triggering deficit")
			n.deficitResolver.TriggerWithReason(node.name)
		}
		node.mutex.Unlock()

		node.SyncToAPIServer()
	}

	n.metricsAPI.SetAllocatedIPs("used", totalUsed)
	n.metricsAPI.SetAllocatedIPs("available", totalAvailable)
	n.metricsAPI.SetAllocatedIPs("needed", totalNeeded)
	n.metricsAPI.SetAvailableENIs(remainingInterfaces)
	n.metricsAPI.SetNodesAtCapacity(nodesAtCapacity)
}
