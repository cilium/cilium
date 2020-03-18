// Copyright 2020 Authors of Cilium
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

package types

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

// AzureStatus is the status of Azure addressing of the node
//
// This struct is embedded into v2.CiliumNode
//
// +k8s:deepcopy-gen=true
type AzureStatus struct {
	// Interfaces is the list of interfaces on the node
	//
	// +optional
	Interfaces []AzureInterface `json:"interfaces,omitempty"`
}

// AzureAddress is an IP address assigned to an AzureInterface
type AzureAddress struct {
	// IP is the ip address of the address
	IP string `json:"ip,omitempty"`

	// Subnet is the subnet the address belongs to
	Subnet string `json:"subnet,omitempty"`

	// State is the provisioning state of the address
	State string `json:"state,omitempty"`
}

// AzureInterface represents an Azure Interface
//
// +k8s:deepcopy-gen=true
type AzureInterface struct {
	// ID is the identifier
	//
	// +optional
	ID string `json:"id,omitempty"`

	// MAC is the mac address
	//
	// +optional
	MAC string `json:"mac,omitempty"`

	// State is the provisioning state
	//
	// +optional
	State string `json:"state,omitempty"`

	// Addresses is the list of all IPs associated with the ENI, including
	// all secondary addresses
	//
	// +optional
	Addresses []AzureAddress `json:"addresses,omitempty"`

	// SecurityGroup is the security group associated with the interface
	SecurityGroup string `json:"security-group,omitempty"`
}

// Instance is the minimal representation of a Azure instance as needed by the
// IPAM plugin
type Instance struct {
	// interfaces is a map of all interfaces attached to the instance
	// indexed by the ID
	Interfaces map[string]*AzureInterface
}

// InstanceMap is the list of all instances indexed by instance ID
type InstanceMap map[string]*Instance

// Update updates the definition of an Azure interface for a particular
// instance. If the interface is already known, the definition is updated,
// otherwise the interface is added to the instance.
func (m InstanceMap) Update(instanceID string, iface *AzureInterface) {
	i, ok := m[instanceID]
	if !ok {
		i = &Instance{}
		m[instanceID] = i
	}

	if i.Interfaces == nil {
		i.Interfaces = map[string]*AzureInterface{}
	}

	i.Interfaces[iface.ID] = iface
}

// Get returns the list of interfaces for a particular instance ID. The
// returned interfaces are deep copied and can be safely accessed but will
// become stale.
func (m InstanceMap) Get(instanceID string) (interfaces []*AzureInterface) {
	if instance, ok := m[instanceID]; ok {
		for _, iface := range instance.Interfaces {
			interfaces = append(interfaces, iface.DeepCopy())
		}
	}

	return
}
