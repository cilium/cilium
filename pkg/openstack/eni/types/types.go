// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/cilium/cilium/pkg/ipam/types"
)

// Spec is the ENI specification of a node. This specification is considered
// by the cilium-operator to act as an IPAM operator and makes ENI IPs available
// via the IPAMSpec section.
//
// The ENI specification can either be provided explicitly by the user or the
// cilium-agent running on the node can be instructed to create the CiliumNode
// custom resource along with an ENI specification when the node registers
// itself to the Kubernetes cluster.
type Spec struct {
	// InstanceType is the ECS instance flavor, e.g. "4c-8G"
	//
	// +kubebuilder:validation:Optional
	InstanceType string `json:"instance-type,omitempty"`

	// AvailabilityZone is the availability zone to use when allocating
	// ENIs.
	//
	// +kubebuilder:validation:Optional
	AvailabilityZone string `json:"availability-zone,omitempty"`

	// VPCID is the network ID to use when allocating ENIs.
	//
	// +kubebuilder:validation:Optional
	VPCID string `json:"vpc-id,omitempty"`

	// CIDR is vpc ipv4 CIDR
	//
	// +kubebuilder:validation:Optional
	CIDR string `json:"cidr,omitempty"`

	// SubnetID is the ID of subnet id of ENI
	//
	// +kubebuilder:validation:Optional
	SubnetID string `json:"subnet-id,omitempty"`

	// SecurityGroups is the list of security groups to attach to any ENI
	// that is created and attached to the instance.
	//
	// +kubebuilder:validation:Optional
	SecurityGroups []string `json:"security-groups,omitempty"`
}

const (
	// ENITypePrimary is the type for ENI
	ENITypePrimary string = "Primary"
	// ENITypeSecondary is the type for ENI
	ENITypeSecondary string = "Secondary"
)

// ENI represents an OpenStack Elastic Network Interface
type ENI struct {
	// ID is the ENI ID
	//
	// +optional
	ID string `json:"id,omitempty"`

	// IP is the primary IP of the ENI
	//
	// +optional
	IP string `json:"ip,omitempty"`

	// MAC is the mac address of the ENI
	//
	// +optional
	MAC string `json:"mac,omitempty"`

	// Type is the ENI type Primary or Secondary
	//
	// +optional
	Type string `json:"type,omitempty"`

	// SecurityGroups are the security groups associated with the ENI
	SecurityGroups []string `json:"security-groups,omitempty"`

	// VPC is the vpc to which the ENI belongs
	//
	// +optional
	VPC VPC `json:"vpc,omitempty"`

	// Subnet is the vSwitch the ENI is using
	//
	// +optional
	Subnet Subnet `json:"subnet,omitempty"`

	// SecondaryIPSets is the list of all secondaryIPs on the ENI
	//
	// +optional
	SecondaryIPSets []PrivateIPSet `json:"secondary-ipsets,omitempty"`
}

// InterfaceID returns the identifier of the interface
func (e *ENI) InterfaceID() string {
	return e.ID
}

// ForeachAddress iterates over all addresses and calls fn
func (e *ENI) ForeachAddress(id string, fn types.AddressIterator) error {
	for _, ipset := range e.SecondaryIPSets {
		if err := fn(id, e.ID, ipset.IpAddress, "", ipset); err != nil {
			return err
		}
	}

	return nil
}

// ENIStatus is the status of ENI addressing of the node
type ENIStatus struct {
	// ENIs is the list of ENIs on the node
	//
	// +optional
	ENIs map[string]ENI `json:"enis,omitempty"`
}

// PrivateIPSet is a nested struct in ecs response
type PrivateIPSet struct {
	IpAddress string `json:"ip-address,omitempty"`
	EniID     string `json:"eni-id,omitempty" `
}

type VPC struct {
	// ID is the vpc to which the ENI belongs
	//
	// +optional
	ID string `json:"id,omitempty"`

	// CIDR is the VPC IPv4 CIDR
	//
	// +optional
	CIDR string `json:"cidr,omitempty"`
}

type Subnet struct {
	// ID is the ID of the subnet
	ID string `json:"id,omitempty"`

	// CIDR is the CIDR range associated with the subnet
	CIDR string `json:"cidr,omitempty"`
}
