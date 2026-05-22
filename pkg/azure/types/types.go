// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam/types"
)

const (
	// ProviderPrefix is the prefix used to indicate that a k8s ProviderID
	// represents an Azure resource
	ProviderPrefix = "azure://"

	// InterfaceAddressLimit is the maximum number of addresses on an interface
	//
	//
	// For more information:
	// https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits?toc=%2fazure%2fvirtual-network%2ftoc.json#networking-limits
	InterfaceAddressLimit = 256

	// StateSucceeded is the address state for a successfully provisioned address
	StateSucceeded = "succeeded"
)

// AzureSpec is the Azure specification of a node running via the Azure IPAM
//
// The Azure specification can either be provided explicitly by the user or the
// cilium agent running on the node can be instructed to create the CiliumNode
// custom resource along with an Azure specification when the node registers
// itself to the Kubernetes cluster.
// This struct is embedded into v2.CiliumNode
type AzureSpec struct {
	// InterfaceName is the name of the interface the cilium-operator
	// will use to allocate all the IPs on
	//
	// +kubebuilder:validation:Optional
	InterfaceName string `json:"interface-name,omitempty"`
}

// AzureStatus is the status of Azure addressing of the node.
// This struct is embedded into v2.CiliumNode
type AzureStatus struct {
	// Interfaces is the list of interfaces on the node
	//
	// +optional
	Interfaces []AzureInterface `json:"interfaces,omitempty"`
}

// AzureAddress is an IP address assigned to an AzureInterface
type AzureAddress struct {
	// IP is the ip address of the address
	//
	// +optional
	IP iputil.Addr `json:"ip,omitzero"`

	// Subnet is the subnet the address belongs to.
	//
	// Deprecated: use AzureInterface.Subnet.ID. Populated as a mirror for one
	// release so external consumers of CiliumNode.Status.Azure can migrate.
	// TODO(https://github.com/cilium/cilium/issues/46074): remove once the migration window closes.
	Subnet string `json:"subnet,omitempty"`

	// State is the provisioning state of the address
	State string `json:"state,omitempty"`
}

// AzureSubnet describes the subnet an AzureInterface is attached to. Azure
// enforces one subnet per NIC, so it is tracked once per interface (mirroring
// the AWS and Alibaba patterns).
type AzureSubnet struct {
	// ID is the resource ID of the subnet
	//
	// +optional
	ID string `json:"id,omitempty"`

	// CIDR is the CIDR range associated with the subnet
	//
	// +optional
	CIDR iputil.Prefix `json:"cidr,omitzero"`
}

// AzureInterface represents an Azure Interface
type AzureInterface struct {
	// ID is the identifier
	//
	// +optional
	ID string `json:"id,omitempty"`

	// IP is the primary IP of the interface
	//
	// +optional
	IP iputil.Addr `json:"ip,omitzero"`

	// Name is the name of the interface
	//
	// +optional
	Name string `json:"name,omitempty"`

	// MAC is the mac address
	//
	// +optional
	MAC string `json:"mac,omitempty"`

	// State is the provisioning state
	//
	// +optional
	State string `json:"state,omitempty"`

	// Addresses is the list of secondary IPs associated with the interface.
	// The primary IP is tracked separately in the IP field, but is also
	// included here when the operator is configured to expose it for
	// allocation.
	//
	// +optional
	Addresses []AzureAddress `json:"addresses,omitempty"`

	// SecurityGroup is the security group associated with the interface
	SecurityGroup string `json:"security-group,omitempty"`

	// Subnet is the subnet the interface is attached to.
	//
	// +optional
	Subnet AzureSubnet `json:"subnet,omitzero"`

	// Gateway is the interface's subnet's default route
	//
	// +optional
	Gateway iputil.Addr `json:"gateway"`

	// CIDR is the range that the interface belongs to.
	//
	// Deprecated: use Subnet.CIDR. Retained for one release so agent/operator
	// rolling upgrades work in either order.
	// TODO(https://github.com/cilium/cilium/issues/46074): remove once the migration window closes.
	//
	// +optional
	CIDR iputil.Prefix `json:"cidr,omitzero"`

	// vmssName is the name of the virtual machine scale set. This field is
	// set by extractIDs()
	vmssName string `json:"-"`

	// vmID is the ID of the virtual machine
	vmID string `json:"-"`

	// resourceGroup is the resource group the interface belongs to
	resourceGroup string `json:"-"`
}

func (a *AzureInterface) DeepCopyInterface() types.Interface {
	return a.DeepCopy()
}

// SetID sets the Azure interface ID, as well as extracting other fields from
// the ID itself.
func (a *AzureInterface) SetID(id string) {
	a.ID = id
	a.extractIDs()
}

// InterfaceID returns the identifier of the interface
func (a *AzureInterface) InterfaceID() string {
	return a.ID
}

// extractIDs extracts resource group name, VMSS name, and VM ID from the
// network interface Azure resource ID. The actual implementation is build-tag
// gated so the Azure SDK is only pulled in by builds that need it (see
// extract_ids.go).
func (a *AzureInterface) extractIDs() {
	a.resourceGroup, a.vmssName, a.vmID = parseAzureResourceID(a.ID)
}

// GetResourceGroup returns the resource group the interface belongs to
func (a *AzureInterface) GetResourceGroup() string {
	return a.resourceGroup
}

// GetVMScaleSetName returns the VM scale set name the interface belongs to
func (a *AzureInterface) GetVMScaleSetName() string {
	return a.vmssName
}

// GetVMID returns the VM ID the interface belongs to
func (a *AzureInterface) GetVMID() string {
	return a.vmID
}
