// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/stats"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/math"
)

type ipamNodeActions interface {
	InstanceID() string
}

// Node represents a node representing an Azure instance
type Node struct {
	// k8sObj is the CiliumNode custom resource representing the node
	k8sObj *v2.CiliumNode

	// node contains the general purpose fields of a node
	node ipamNodeActions

	// manager is the Azure node manager responsible for this node
	manager *InstancesManager
}

// UpdatedNode is called when an update to the CiliumNode is received.
func (n *Node) UpdatedNode(obj *v2.CiliumNode) {
	n.k8sObj = obj
}

// PopulateStatusFields fills in the status field of the CiliumNode custom
// resource with Azure specific information
func (n *Node) PopulateStatusFields(k8sObj *v2.CiliumNode) {
	k8sObj.Status.Azure.Interfaces = []types.AzureInterface{}

	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()
	n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.InterfaceRevision) error {
		iface, ok := interfaceObj.Resource.(*types.AzureInterface)
		if ok {
			k8sObj.Status.Azure.Interfaces = append(k8sObj.Status.Azure.Interfaces, *(iface.DeepCopy()))
		}
		return nil
	})
}

// PrepareIPRelease prepares the release of IPs
func (n *Node) PrepareIPRelease(excessIPs int, scopedLog *logrus.Entry, family ipam.Family) *ipam.ReleaseAction {
	return &ipam.ReleaseAction{}
}

// ReleaseIPs performs the IP release operation
func (n *Node) ReleaseIPs(ctx context.Context, r *ipam.ReleaseAction) error {
	return fmt.Errorf("not implemented")
}

// PrepareIPAllocation returns the number of IP addresses that can be allocated/created
// based on the provided IP family.
func (n *Node) PrepareIPAllocation(scopedLog *logrus.Entry, family ipam.Family) (a *ipam.AllocationAction, err error) {
	a = &ipam.AllocationAction{}

	if family == ipam.IPv6 {
		return a, fmt.Errorf("ipv6 allocation is not implemented")
	}

	requiredIfaceName := n.k8sObj.Spec.Azure.InterfaceName
	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()
	err = n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.InterfaceRevision) error {
		iface, ok := interfaceObj.Resource.(*types.AzureInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}

		availableOnInterface, available := isAvailableInterface(requiredIfaceName, iface, scopedLog)
		if !available {
			return nil
		}

		a.IPv4.InterfaceCandidates++

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

			poolID, available := n.manager.subnets.FirstSubnetWithAvailableAddresses(preferredPoolIDs)
			if poolID != ipamTypes.PoolNotExists {
				scopedLog.WithFields(logrus.Fields{
					"subnetID":           poolID,
					"availableAddresses": available,
				}).Debug("Subnet has IPs available")

				a.InterfaceID = iface.ID
				a.Interface = interfaceObj
				a.PoolID = poolID
				a.IPv4.AvailableForAllocation = math.IntMin(available, availableOnInterface)
			}
		}
		return nil
	})

	return
}

// AllocateIPs performs the Azure IP address allocation operation based on the provided IP family.
func (n *Node) AllocateIPs(ctx context.Context, a *ipam.AllocationAction, family ipam.Family) error {
	if family == ipam.IPv6 {
		return fmt.Errorf("ipv6 allocation is not implemented")
	}

	iface, ok := a.Interface.Resource.(*types.AzureInterface)
	if !ok {
		return fmt.Errorf("invalid interface object")
	}

	if iface.GetVMScaleSetName() == "" {
		return n.manager.api.AssignPrivateIpAddressesVM(ctx, string(a.PoolID), iface.Name, a.IPv4.AvailableForAllocation)
	} else {
		return n.manager.api.AssignPrivateIpAddressesVMSS(ctx, iface.GetVMID(), iface.GetVMScaleSetName(), string(a.PoolID), iface.Name, a.IPv4.AvailableForAllocation)
	}
}

// CreateInterface is called to create a new interface based on the provided IP family.
// This operation is currently not supported on Azure.
func (n *Node) CreateInterface(ctx context.Context, allocation *ipam.AllocationAction, scopedLog *logrus.Entry, family ipam.Family) (int, string, error) {
	return 0, "", fmt.Errorf("not implemented")
}

// ResyncInterfacesAndIPs is called to retrieve interfaces and IPs known
// to the Azure API based on the provided IP family and returns them.
func (n *Node) ResyncInterfacesAndIPs(ctx context.Context, scopedLog *logrus.Entry, family ipam.Family) (
	available ipamTypes.AllocationMap,
	stats stats.InterfaceStats,
	err error) {

	if family == ipam.IPv6 {
		return available, stats, fmt.Errorf("ipv6 allocation is not implemented")
	}

	// Azure virtual machines always have an upper limit of 256 addresses.
	// Both VMs and NICs can have a maximum of 256 addresses, so as long as
	// there is at least one available NIC, we can allocate up to 256 addresses
	// on the VM (minus the primary IP address).
	stats.NodeCapacity = math.IntMax(n.GetMaximumAllocatableIP(family)-1, 0)

	if n.node.InstanceID() == "" {
		return nil, stats, nil
	}

	available = ipamTypes.AllocationMap{}
	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()
	err = n.manager.instances.ForeachAddress(n.node.InstanceID(), func(instanceID, interfaceID, ip, poolID string, addressObj ipamTypes.Address) error {
		address, ok := addressObj.(types.AzureAddress)
		if !ok {
			scopedLog.WithField("ip", ip).Warning("Not an Azure address object, ignoring IP")
			return nil
		}

		if address.State == types.StateSucceeded {
			available[address.IP] = ipamTypes.AllocationIP{Resource: interfaceID}
		} else {
			scopedLog.WithFields(logrus.Fields{
				"ip":    address.IP,
				"state": address.State,
			}).Warning("Ignoring potentially available IP due to non-successful state")
		}
		return nil
	})
	if err != nil {
		return nil, stats, err
	}

	requiredIfaceName := n.k8sObj.Spec.Azure.InterfaceName
	err = n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.InterfaceRevision) error {
		iface, ok := interfaceObj.Resource.(*types.AzureInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}

		_, available := isAvailableInterface(requiredIfaceName, iface, scopedLog)
		if available {
			stats.RemainingAvailableInterfaceCount++
		}
		return nil
	})
	if err != nil {
		return nil, stats, err
	}

	return available, stats, nil
}

// GetMaximumAllocatableIP returns the maximum amount of IP addresses
// that can be allocated to the instance based on the provided IP family.
func (n *Node) GetMaximumAllocatableIP(family ipam.Family) int {
	if family == ipam.IPv6 {
		// not implemented
		return 0
	}
	// An Azure node can allocate up to 256 private IP addresses
	// source: https://github.com/MicrosoftDocs/azure-docs/blob/master/includes/azure-virtual-network-limits.md#networking-limits---azure-resource-manager
	return types.InterfaceAddressLimit
}

// GetMinimumAllocatableIP returns the minimum amount of IP addresses that
// must be allocated to the instance based on the provided IP family.
func (n *Node) GetMinimumAllocatableIP(family ipam.Family) int {
	if family == ipam.IPv6 {
		// not implemented
		return 0
	}
	return defaults.IPAMPreAllocation
}

func (n *Node) IsPrefixDelegated(family ipam.Family) bool {
	return false
}

func (n *Node) GetUsedIPWithPrefixes(family ipam.Family) int {
	if n.k8sObj == nil {
		return 0
	}
	if family == ipam.IPv6 {
		return len(n.k8sObj.Status.IPAM.IPv6Used)
	}
	return len(n.k8sObj.Status.IPAM.Used)
}

// isAvailableInterface returns whether interface is available and the number of available IPs to allocate in interface
func isAvailableInterface(requiredIfaceName string, iface *types.AzureInterface, scopedLog *logrus.Entry) (availableOnInterface int, available bool) {
	if requiredIfaceName != "" {
		if iface.Name != requiredIfaceName {
			scopedLog.WithFields(logrus.Fields{
				"ifaceName":    iface.Name,
				"requiredName": requiredIfaceName,
			}).Debug("Not considering interface as available since it does not match the required name")
			return 0, false
		}
	}

	scopedLog.WithFields(logrus.Fields{
		"id":           iface.ID,
		"numAddresses": len(iface.Addresses),
	}).Debug("Considering interface as available")

	availableOnInterface = math.IntMax(types.InterfaceAddressLimit-len(iface.Addresses), 0)
	if availableOnInterface <= 0 {
		return 0, false
	}
	return availableOnInterface, true
}
