// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/spf13/cast"

	"github.com/cilium/cilium/pkg/ipam/types"
)

const (
	ENIStatusInUse     = "InUse"
	ENIStatusAvailable = "Available"
	ENIStatusAttaching = "Attaching"
	ENIStatusDetaching = "Detaching"
	ENIStatusCreating  = "Creating"
	ENIStatusDeleting  = "Deleting"
)

// Spec is the ENI specification of a node. This specification is considered
// by the cilium-operator to act as an IPAM operator and makes ENI IPs available
// via the IPAMSpec section.
//
// The ENI specification can either be provided explicitly by the user or the
// cilium agent running on the node can be instructed to create the CiliumNode
// custom resource along with an ENI specification when the node registers
// itself to the Kubernetes cluster.
type Spec struct {
	// InstanceType is the Volcengine ECS instance type, e.g. "ecs.g2ine.large"
	//
	// +kubebuilder:validation:Optional
	InstanceType string `json:"instance-type,omitempty"`

	// AvailabilityZone is the availability zone to use when allocating
	// ENIs.
	//
	// +kubebuilder:validation:Optional
	AvailabilityZone string `json:"availability-zone,omitempty"`

	// ProjectName is the project name to use for resource management.
	//
	// +kubebuilder:validation:Optional
	ProjectName string `json:"project-name,omitempty"`

	// VPCID is the VPC ID to use when allocating ENIs.
	//
	// +kubebuilder:validation:Optional
	VPCID string `json:"vpc-id,omitempty"`

	// CIDRBlock is VPC IPv4 CIDR
	//
	// +kubebuilder:validation:Optional
	CIDRBlock string `json:"cidr-block,omitempty"`

	// SubnetIDs is the list of subnet ids to use when evaluating what Volcengine
	// subnets to use for ENI and IP allocation.
	//
	// +kubebuilder:validation:Optional
	SubnetIDs []string `json:"subnet-ids,omitempty"`

	// SubnetTags is the list of tags to use when evaluating what Volcengine
	// subnets to use for ENI and IP allocation.
	//
	// +kubebuilder:validation:Optional
	SubnetTags map[string]string `json:"subnet-tags,omitempty"`

	// ENITags is the list of tags to use when evaluating what Volcengine
	// ENIs to use for IP allocation.
	//
	// +kubebuilder:validation:Optional
	ENITags map[string]string `json:"eni-tags,omitempty"`

	// SecurityGroups is the list of security groups to attach to any ENI
	// that is created and attached to the instance.
	//
	// +kubebuilder:validation:Optional
	SecurityGroups []string `json:"security-groups,omitempty"`

	// SecurityGroupTags is the list of tags to use when evaluating which
	// security groups to use for the ENI.
	//
	// +kubebuilder:validation:Optional
	SecurityGroupTags map[string]string `json:"security-group-tags,omitempty"`

	// UsePrimaryAddress determines whether a primary address of Volcengine ENI
	// should be available for allocations on the node
	//
	// +kubebuilder:validation:Optional
	UsePrimaryAddress *bool `json:"use-primary-address,omitempty"`
}

func (s *Spec) EnableUsePrimaryAddress() bool {
	return cast.ToBool(s.UsePrimaryAddress)
}

type ENIType string

const (
	// ENITypePrimary is the type for primary ENI
	ENITypePrimary ENIType = "primary"
	// ENITypeSecondary is the type for secondary ENI
	ENITypeSecondary ENIType = "secondary"
)

// ENI represents a Volcengine Network Interface
type ENI struct {
	// NetworkInterfaceID is the ENI ID
	NetworkInterfaceID string `json:"network-interface-id,omitempty"`

	// ProjectName is the project name the ENI belongs to
	ProjectName string `json:"project-name,omitempty"`

	// Type is the type of the ENI Primary or Secondary
	Type ENIType `json:"type,omitempty"`

	// MACAddress is the MAC address of the ENI
	MACAddress string `json:"mac-address,omitempty"`

	// PrimaryIPAddress is the primary private IPv4 address of the ENI
	PrimaryIPAddress string `json:"primary-ip-address,omitempty"`

	// PrivateIPSets is the list of all private IP addresses of the ENI
	PrivateIPSets []PrivateIPSet `json:"private-ipsets,omitempty"`

	// VPC is the VPC to which the ENI is attached
	VPC VPC `json:"vpc,omitempty"`

	// ZoneID is the zone to which the ENI is attached
	ZoneID string `json:"zone-id,omitempty"`

	// Subnet is the subnet to which the ENI is attached
	Subnet Subnet `json:"subnet,omitempty"`

	// DeviceID is the ID of the instance to which the ENI is attached
	DeviceID string `json:"device-id,omitempty"`

	// SecurityGroupIDs is the list of security group IDs associated with the ENI
	SecurityGroupIds []string `json:"security-group-ids,omitempty"`

	// Tags is the set of tags associated with the ENI
	//
	// +optional
	Tags map[string]string `json:"tags,omitempty"`
}

// InterfaceID returns the identifier of the interface
func (e *ENI) InterfaceID() string {
	return e.NetworkInterfaceID
}

// ForeachAddress iterates over all addresses and calls fn
func (e *ENI) ForeachAddress(id string, fn types.AddressIterator) error {
	for _, address := range e.PrivateIPSets {
		if address.Primary {
			continue
		}
		if err := fn(id, e.NetworkInterfaceID, address.PrivateIpAddress, "", address); err != nil {
			return err
		}
	}

	return nil
}

type VPC struct {
	// VPCID is the ID of the VPC
	VPCID string `json:"vpc-id,omitempty"`

	// CIDRBlock is the IPv4 CIDR of the VPC
	//
	// +optional
	CIDRBlock string `json:"cidr-block,omitempty"`

	// IPv6CIDRBlock is the IPv6 CIDR of the VPC
	//
	// +optional
	IPv6CIDRBlock string `json:"ipv6-cidr-block,omitempty"`

	// SecondaryCIDRBlocks is the list of secondary CIDR blocks of the VPC
	//
	// +optional
	SecondaryCIDRBlocks []string `json:"secondary-cidr-blocks,omitempty"`
}

// Subnet stores the information about a Volcengine subnet
type Subnet struct {
	// SubnetID is the ID of the subnet
	SubnetID string `json:"subnet-id,omitempty"`

	// CIDRBlock is the IPv4 CIDR of the subnet
	//
	// +optional
	CIDRBlock string `json:"cidr-block,omitempty"`

	// IPv6CIDRBlock is the IPv6 CIDR of the subnet
	//
	// +optional
	IPv6CIDRBlock string `json:"ipv6-cidr-block,omitempty"`
}

// PrivateIPSet stores the information about a private IP address
type PrivateIPSet struct {
	PrivateIpAddress string `json:"private-ip-address,omitempty"`
	Primary          bool   `json:"primary,omitempty" `
}

// ENIStatus is the status of ENI addressing of the node
type ENIStatus struct {
	// ENIs is the list of ENIs on the node
	//
	// +optional
	ENIs map[string]ENI `json:"enis,omitempty"`
}
