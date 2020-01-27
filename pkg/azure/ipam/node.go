// Copyright 2019-2020 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/sirupsen/logrus"
)

const (
	// maxAttachRetries is the maximum number of attachment retries
	maxAttachRetries = 5
)

// Node represents a node representing an Azure instance
type Node struct {
	mutex lock.RWMutex

	// node contains the general purpose fields of a node
	node *ipam.Node

	// interfaces is the list of interfaces attached to the node indexed by ID.
	// Protected by Node.mutex.
	interfaces map[string]v2.AzureInterface

	// k8sObj is the CiliumNode custom resource representing the node
	k8sObj *v2.CiliumNode

	// manager is the Azure node manager responsible for this node
	manager *InstancesManager
}

// UpdatedNode is called when an update to the CiliumNode is received.
func (n *Node) UpdatedNode(obj *v2.CiliumNode) {
	n.k8sObj = obj
}

func (n *Node) GetMaxAboveWatermark() int {
	return n.k8sObj.Spec.IPAM.MaxAboveWatermark
}

func (n *Node) GetPreAllocate() int {
	if n.k8sObj.Spec.IPAM.PreAllocate != 0 {
		return n.k8sObj.Spec.IPAM.PreAllocate
	}
	return defaults.ENIPreAllocation
}

func (n *Node) GetMinAllocate() int {
	return n.k8sObj.Spec.IPAM.MinAllocate
}

// PopulateStatusFields fills in the status field of the CiliumNode custom
// resource with ENI specific information
func (n *Node) PopulateStatusFields(k8sObj *v2.CiliumNode) {
	n.mutex.RLock()
	k8sObj.Status.Azure.Interfaces = map[string]v2.AzureInterface{}
	for _, iface := range n.interfaces {
		k8sObj.Status.Azure.Interfaces[iface.ID] = iface
	}
	n.mutex.RUnlock()
}

// PopulateSpecFields fills in the spec field of the CiliumNode custom resource
// with ENI specific information
func (n *Node) PopulateSpecFields(k8sObj *v2.CiliumNode) {
}

// PrepareIPRelease prepares the release of IPs
func (n *Node) PrepareIPRelease(excessIPs int, scopedLog *logrus.Entry) *ipam.ReleaseAction {
	return &ipam.ReleaseAction{}
}

// ReleaseIPs performs the IP release operation
func (n *Node) ReleaseIPs(ctx context.Context, r *ipam.ReleaseAction) error {
	return fmt.Errorf("not implemented")
}

// PrepareIPAllocation returns the number of IPs that can be allocated/created.
func (n *Node) PrepareIPAllocation(scopedLog *logrus.Entry) (a *ipam.AllocationAction, err error) {
	return &ipam.AllocationAction{}, nil
}

// AllocateIPs performs the ENI allocation oepration
func (n *Node) AllocateIPs(ctx context.Context, a *ipam.AllocationAction) error {
	return fmt.Errorf("not implemented")
}

func (n *Node) CreateInterface(ctx context.Context, allocation *ipam.AllocationAction, scopedLog *logrus.Entry) (int, string, error) {
	return 0, "", fmt.Errorf("not implemented")
}

// LogFields extends the log entry with Azure IPAM specific fields
func (n *Node) LogFields(logger *logrus.Entry) *logrus.Entry {
	return logger
}

// ResyncInterfacesAndIPs is called to retrieve and ENIs and IPs as known to
// the EC2 API and return them
func (n *Node) ResyncInterfacesAndIPs(ctx context.Context, scopedLog *logrus.Entry) (map[string]v2.AllocationIP, error) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	available := map[string]v2.AllocationIP{}
	n.interfaces = map[string]v2.AzureInterface{}
	interfaces := n.manager.GetInterfaces(n.k8sObj.Name)
	for _, iface := range interfaces {
		n.interfaces[iface.ID] = *iface

		for _, ip := range iface.Addresses {
			available[ip] = v2.AllocationIP{Resource: iface.ID}
		}
	}

	return available, nil
}
