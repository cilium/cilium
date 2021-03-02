// Copyright 2021 Authors of Cilium
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
	// InstanceType is the ECS instance type, e.g. "ecs.g6.2xlarge"
	//
	// +kubebuilder:validation:Optional
	InstanceType string `json:"instance-type,omitempty"`

	// AvailabilityZone is the availability zone to use when allocating
	// ENIs.
	//
	// +kubebuilder:validation:Optional
	AvailabilityZone string `json:"availability-zone,omitempty"`

	// VPCID is the VPC ID to use when allocating ENIs.
	//
	// +kubebuilder:validation:Optional
	VPCID string `json:"vpc-id,omitempty"`

	// CIDRBlock is vpc ipv4 CIDR
	//
	// +kubebuilder:validation:Optional
	CIDRBlock string `json:"cidr-block,omitempty"`

	// VSwitches is the ID of vSwitch available for ENI
	//
	// +kubebuilder:validation:Optional
	VSwitches []string `json:"vswitches,omitempty"`

	// VSwitchTags is the list of tags to use when evaluating which
	// vSwitch to use for the ENI.
	//
	// +kubebuilder:validation:Optional
	VSwitchTags map[string]string `json:"vswitch-tags,omitempty"`

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
}

const (
	// ENITypePrimary is the type for ENI
	ENITypePrimary string = "Primary"
	// ENITypeSecondary is the type for ENI
	ENITypeSecondary string = "Secondary"
)

// ENI represents an AlibabaCloud Elastic Network Interface
type ENI struct {
	// NetworkInterfaceID is the ENI id
	//
	// +optional
	NetworkInterfaceID string `json:"network-interface-id,omitempty"`

	// MACAddress is the mac address of the ENI
	//
	// +optional
	MACAddress string `json:"mac-address,omitempty"`

	// Type is the ENI type Primary or Secondary
	//
	// +optional
	Type string `json:"type,omitempty"`

	// InstanceID is the InstanceID using this ENI
	//
	// +optional
	InstanceID string `json:"instance-id,omitempty"`

	// SecurityGroupIDs is the security group ids used by this ENI
	//
	// +optional
	SecurityGroupIDs []string `json:"security-groupids,omitempty"`

	// VPC is the vpc to which the ENI belongs
	//
	// +optional
	VPC VPC `json:"vpc,omitempty"`

	// ZoneID is the zone to which the ENI belongs
	//
	// +optional
	ZoneID string `json:"zone-id,omitempty"`

	// VSwitch is the vSwitch the ENI is using
	//
	// +optional
	VSwitch VSwitch `json:"vswitch,omitempty"`

	// PrimaryIPAddress is the primary IP on ENI
	//
	// +optional
	PrimaryIPAddress string `json:"primary-ip-address,omitempty"`

	// PrivateIPSets is the list of all IPs on the ENI, including PrimaryIPAddress
	//
	// +optional
	PrivateIPSets []PrivateIPSet `json:"private-ipsets,omitempty"`

	// Tags is the tags on this ENI
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

// ENIStatus is the status of ENI addressing of the node
type ENIStatus struct {
	// ENIs is the list of ENIs on the node
	//
	// +optional
	ENIs map[string]ENI `json:"enis,omitempty"`
}

// PrivateIPSet is a nested struct in ecs response
type PrivateIPSet struct {
	PrivateIpAddress string `json:"private-ip-address,omitempty"`
	Primary          bool   `json:"primary,omitempty" `
}

type VPC struct {
	// VPCID is the vpc to which the ENI belongs
	//
	// +optional
	VPCID string `json:"vpc-id,omitempty"`

	// CIDRBlock is the VPC IPv4 CIDR
	//
	// +optional
	CIDRBlock string `json:"cidr,omitempty"`

	// IPv6CIDRBlock is the VPC IPv6 CIDR
	//
	// +optional
	IPv6CIDRBlock string `json:"ipv6-cidr,omitempty"`
}

type VSwitch struct {
	// VSwitchID is the vSwitch to which the ENI belongs
	//
	// +optional
	VSwitchID string `json:"vswitch-id,omitempty"`

	// CIDRBlock is the vSwitch IPv4 CIDR
	//
	// +optional
	CIDRBlock string `json:"cidr,omitempty"`

	// IPv6CIDRBlock is the vSwitch IPv6 CIDR
	//
	// +optional
	IPv6CIDRBlock string `json:"ipv6-cidr,omitempty"`
}
