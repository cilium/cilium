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
	"strings"

	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/math"

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

	// k8sObj is the CiliumNode custom resource representing the node
	k8sObj *v2.CiliumNode

	// manager is the Azure node manager responsible for this node
	manager *InstancesManager
}

// UpdatedNode is called when an update to the CiliumNode is received.
func (n *Node) UpdatedNode(obj *v2.CiliumNode) {
	n.k8sObj = obj
}

func (n *Node) instanceIdLocked() (id string) {
	if n.k8sObj != nil {
		id = strings.ToLower(n.k8sObj.Spec.Azure.InstanceID)
	}
	return
}

// PopulateStatusFields fills in the status field of the CiliumNode custom
// resource with Azure specific information
func (n *Node) PopulateStatusFields(k8sObj *v2.CiliumNode) {
	n.mutex.RLock()
	k8sObj.Status.Azure.Interfaces = []types.AzureInterface{}
	for _, iface := range n.manager.GetInterfaces(n.instanceIdLocked()) {
		k8sObj.Status.Azure.Interfaces = append(k8sObj.Status.Azure.Interfaces, *iface)
	}
	n.mutex.RUnlock()
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
	a = &ipam.AllocationAction{}

	for _, iface := range n.manager.GetInterfaces(n.instanceIdLocked()) {
		scopedLog.WithFields(logrus.Fields{
			"id":           iface.ID,
			"numAddresses": len(iface.Addresses),
		}).Debug("Considering interface for allocation")

		availableOnInterface := math.IntMax(types.InterfaceAddressLimit-len(iface.Addresses), 0)
		if availableOnInterface <= 0 {
			continue
		} else {
			a.AvailableInterfaces++
		}

		if a.InterfaceID == "" {
			scopedLog.WithFields(logrus.Fields{
				"id":                   iface.ID,
				"availableOnInterface": availableOnInterface,
			}).Debug("Interface has IPs available")

			preferredPoolIDs := []ipamTypes.PoolID{}
			for _, address := range iface.Addresses {
				if address.Subnet != "" {
					preferredPoolIDs = append(preferredPoolIDs, ipamTypes.PoolID(address.Subnet))
				}
			}

			poolID, available := n.manager.getAllocator().FirstPoolWithAvailableQuota(preferredPoolIDs)
			if poolID != ipamTypes.PoolNotExists {
				scopedLog.WithFields(logrus.Fields{
					"subnetID":           poolID,
					"availableAddresses": available,
				}).Debug("Subnet has IPs available")

				a.InterfaceID = iface.ID
				a.PoolID = poolID
				a.AvailableForAllocation = math.IntMin(available, availableOnInterface)
			}
		}
	}

	return
}

// AllocateIPs performs the Azure IP allocation operation
func (n *Node) AllocateIPs(ctx context.Context, a *ipam.AllocationAction) error {
	ips, err := n.manager.getAllocator().AllocateMany(a.PoolID, a.AvailableForAllocation)
	if err != nil {
		return err
	}

	err = n.manager.api.AssignPrivateIpAddresses(ctx, string(a.PoolID), a.InterfaceID, ips)
	if err != nil {
		n.manager.getAllocator().ReleaseMany(a.PoolID, ips)
		return err
	}

	return nil
}

// CreateInterface is called to create a new interface. This operation is
// currently not supported on Azure.
func (n *Node) CreateInterface(ctx context.Context, allocation *ipam.AllocationAction, scopedLog *logrus.Entry) (int, string, error) {
	return 0, "", fmt.Errorf("not implemented")
}

// LogFields extends the log entry with Azure IPAM specific fields
func (n *Node) LogFields(logger *logrus.Entry) *logrus.Entry {
	if n.k8sObj != nil {
		logger = logger.WithField("instanceID", n.k8sObj.Spec.Azure.InstanceID)
	}
	return logger
}

// ResyncInterfacesAndIPs is called to retrieve and interfaces and IPs as known
// to the Azure API and return them
func (n *Node) ResyncInterfacesAndIPs(ctx context.Context, scopedLog *logrus.Entry) (ipamTypes.AllocationMap, error) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if n.k8sObj.Spec.Azure.InstanceID == "" {
		return nil, nil
	}

	available := ipamTypes.AllocationMap{}
	interfaces := n.manager.GetInterfaces(n.instanceIdLocked())
	for _, iface := range interfaces {
		for _, address := range iface.Addresses {
			if address.State == types.StateSucceeded {
				available[address.IP] = ipamTypes.AllocationIP{Resource: iface.ID}
			} else {
				log.WithFields(logrus.Fields{
					"ip":    address.IP,
					"state": address.State,
				}).Warning("Ignoring potentially available IP due to non-successful state")
			}
		}
	}

	return available, nil
}
