// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/cilium/operator/pkg/ipam/nodemanager"
	"github.com/cilium/cilium/operator/pkg/ipam/stats"
	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/defaults"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
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

	// vmss is the Azure VM Scale Set the node belongs to (optional)
	vmss string
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
	n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.Interface) error {
		iface, ok := interfaceObj.(*types.AzureInterface)
		if ok {
			k8sObj.Status.Azure.Interfaces = append(k8sObj.Status.Azure.Interfaces, *(iface.DeepCopy()))
		}
		return nil
	})
}

// PrepareIPRelease prepares the release of IPs
func (n *Node) PrepareIPRelease(excessIPs int, scopedLog *slog.Logger) *nodemanager.ReleaseAction {
	return &nodemanager.ReleaseAction{}
}

// ReleaseIPPrefixes is a no-op on Azure since Azure ENIs don't
// support prefix delegation.
func (n *Node) ReleaseIPPrefixes(ctx context.Context, r *nodemanager.ReleaseAction) error {
	// nothing to do
	return nil
}

// ReleaseIPs performs the IP release operation
func (n *Node) ReleaseIPs(ctx context.Context, r *nodemanager.ReleaseAction) error {
	return fmt.Errorf("not implemented")
}

// PrepareIPAllocation returns the number of IPs that can be allocated/created.
func (n *Node) PrepareIPAllocation(scopedLog *slog.Logger) (a *nodemanager.AllocationAction, err error) {
	a = &nodemanager.AllocationAction{}
	requiredIfaceName := n.k8sObj.Spec.Azure.InterfaceName
	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()
	usePrimary := n.manager.usePrimary
	err = n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.Interface) error {
		iface, ok := interfaceObj.(*types.AzureInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}

		availableOnInterface, available := isAvailableInterface(requiredIfaceName, iface, usePrimary, scopedLog)
		if !available {
			return nil
		}

		a.IPv4.InterfaceCandidates++

		if a.InterfaceID == "" {
			scopedLog.Debug(
				"Interface has IPs available",
				logfields.ID, iface.ID,
				logfields.AvailableAddresses, availableOnInterface,
			)

			var preferredPoolIDs []ipamTypes.PoolID
			if iface.Subnet.ID != "" {
				preferredPoolIDs = []ipamTypes.PoolID{ipamTypes.PoolID(iface.Subnet.ID)}
			}

			poolID, available := n.manager.subnets.FirstSubnetWithAvailableAddresses(preferredPoolIDs)
			if poolID != ipamTypes.PoolNotExists {
				scopedLog.Debug(
					"Subnet has IPs available",
					logfields.SubnetID, poolID,
					logfields.AvailableAddresses, available,
				)

				a.InterfaceID = iface.ID
				a.Interface = interfaceObj
				a.PoolID = poolID
				a.IPv4.AvailableForAllocation = min(available, availableOnInterface)
			}
		}
		return nil
	})

	return
}

// AllocateIPs performs the Azure IP allocation operation
func (n *Node) AllocateIPs(ctx context.Context, a *nodemanager.AllocationAction) error {
	iface, ok := a.Interface.(*types.AzureInterface)
	if !ok {
		return fmt.Errorf("invalid interface object")
	}

	if iface.GetVMScaleSetName() == "" {
		return n.manager.api.AssignPrivateIpAddressesVM(ctx, string(a.PoolID), iface.Name, a.IPv4.AvailableForAllocation)
	} else {
		return n.manager.api.AssignPrivateIpAddressesVMSS(ctx, iface.GetVMID(), iface.GetVMScaleSetName(), string(a.PoolID), iface.Name, a.IPv4.AvailableForAllocation)
	}
}

func (n *Node) AllocateStaticIP(ctx context.Context, staticIPTags ipamTypes.Tags) (string, error) {
	if n.vmss == "" {
		return n.manager.api.AssignPublicIPAddressesVM(ctx, n.node.InstanceID(), staticIPTags)
	}
	return n.manager.api.AssignPublicIPAddressesVMSS(ctx, n.node.InstanceID(), n.vmss, staticIPTags)
}

// CreateInterface is called to create a new interface. This operation is
// currently not supported on Azure.
func (n *Node) CreateInterface(ctx context.Context, allocation *nodemanager.AllocationAction, scopedLog *slog.Logger) (int, string, error) {
	return 0, "", fmt.Errorf("not implemented")
}

// ResyncInterfacesAndIPs is called to retrieve interfaces and IPs known
// to the Azure API and return them
func (n *Node) ResyncInterfacesAndIPs(ctx context.Context, scopedLog *slog.Logger) (
	available ipamTypes.AllocationMap,
	stats stats.InterfaceStats,
	err error) {

	if n.node.InstanceID() == "" {
		return nil, stats, nil
	}

	available = ipamTypes.AllocationMap{}
	n.manager.mutex.RLock()
	defer n.manager.mutex.RUnlock()
	usePrimary := n.manager.usePrimary

	// Azure caps both NICs and VMs at 256 addresses; start from that ceiling
	// and decrement per NIC below for any primary slot we can't allocate.
	nodeCapacity := types.InterfaceAddressLimit
	requiredIfaceName := n.k8sObj.Spec.Azure.InterfaceName
	err = n.manager.instances.ForeachInterface(n.node.InstanceID(), func(instanceID, interfaceID string, interfaceObj ipamTypes.Interface) error {
		iface, ok := interfaceObj.(*types.AzureInterface)
		if !ok {
			return fmt.Errorf("invalid interface object")
		}

		for _, address := range iface.Addresses {
			if address.State == types.StateSucceeded {
				available[address.IP.String()] = ipamTypes.AllocationIP{Resource: interfaceID}
			} else {
				scopedLog.Warn(
					"Ignoring potentially available IP due to non-successful state",
					logfields.IPAddr, address.IP,
					logfields.State, address.State,
				)
			}
		}

		// Cache the VMSS name from the first interface we see
		if n.vmss == "" {
			n.vmss = iface.GetVMScaleSetName()
		}

		// The primary IP still consumes a NIC slot even when it is not
		// allocatable; reserve it from the VM-wide budget.
		if !usePrimary && iface.IP.IsValid() {
			nodeCapacity--
		}

		if _, isAvailable := isAvailableInterface(requiredIfaceName, iface, usePrimary, scopedLog); isAvailable {
			stats.RemainingAvailableInterfaceCount++
		}
		return nil
	})
	if err != nil {
		return nil, stats, err
	}
	stats.NodeCapacity = max(nodeCapacity, 0)

	return available, stats, nil
}

// GetMaximumAllocatableIPv4 returns the maximum amount of IPv4 addresses
// that can be allocated to the instance
func (n *Node) GetMaximumAllocatableIPv4() int {
	// An Azure node can allocate up to 256 private IP addresses
	// source: https://github.com/MicrosoftDocs/azure-docs/blob/master/includes/azure-virtual-network-limits.md#networking-limits---azure-resource-manager
	return types.InterfaceAddressLimit
}

// GetMinimumAllocatableIPv4 returns the minimum amount of IPv4 addresses that
// must be allocated to the instance.
func (n *Node) GetMinimumAllocatableIPv4() int {
	return defaults.IPAMPreAllocation
}

func (n *Node) IsPrefixDelegated() bool {
	return false
}

// GetAttachedCIDRs is a no-op since Azure does not use multi-pool but uses
// the CRD allocator.
func (n *Node) GetAttachedCIDRs() []netip.Prefix {
	return nil
}

// PrepareCIDRRelease is a no-op since Azure does not use multi-pool but uses
// the CRD allocator, that's backed by PrepareIPRelease
func (n *Node) PrepareCIDRRelease(_ []netip.Prefix) []*nodemanager.ReleaseAction {
	return nil
}

// ReleaseCIDRs is a no-op since Azure does not use multi-pool but uses the
// CRD allocator, that's backed by ReleaseIPs/ReleaseIPPrefixes
func (n *Node) ReleaseCIDRs(_ context.Context, _ *nodemanager.ReleaseAction) ([]netip.Prefix, error) {
	return nil, nil
}

// isAvailableInterface returns whether interface is available and the number of available IPs to allocate in interface
func isAvailableInterface(requiredIfaceName string, iface *types.AzureInterface, usePrimary bool, scopedLog *slog.Logger) (availableOnInterface int, available bool) {
	if requiredIfaceName != "" {
		if iface.Name != requiredIfaceName {
			scopedLog.Debug(
				"Not considering interface as available since it does not match the required name",
				logfields.Interface, iface.Name,
				logfields.Required, requiredIfaceName,
			)
			return 0, false
		}
	}

	scopedLog.Debug(
		"Considering interface as available",
		logfields.ID, iface.ID,
		logfields.NumAddresses, len(iface.Addresses),
	)

	// The 256-address NIC limit covers both the primary and any secondaries.
	// When the primary is not exposed to the pool, its slot is consumed but
	// not reflected in iface.Addresses, so reserve it here.
	limit := types.InterfaceAddressLimit
	if !usePrimary && iface.IP.IsValid() {
		limit--
	}
	availableOnInterface = max(limit-len(iface.Addresses), 0)
	if availableOnInterface <= 0 {
		return 0, false
	}
	return availableOnInterface, true
}
