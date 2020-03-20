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

// ENISpec is the ENI specification of a node. This specification is considered
// by the cilium-operator to act as an IPAM operator and makes ENI IPs available
// via the IPAMSpec section.
//
// The ENI specification can either be provided explicitly by the user or the
// cilium agent running on the node can be instructed to create the CiliumNode
// custom resource along with an ENI specification when the node registers
// itself to the Kubernetes cluster.
type ENISpec struct {
	// InstanceID is the AWS InstanceId of the node. The InstanceID is used
	// to retrieve AWS metadata for the node.
	//
	// OBSOLETE: This field is obsolete, please use Spec.InstanceID
	InstanceID string `json:"instance-id,omitempty"`

	// InstanceType is the AWS EC2 instance type, e.g. "m5.large"
	InstanceType string `json:"instance-type,omitempty"`

	// MinAllocate is the minimum number of IPs that must be allocated when
	// the node is first bootstrapped. It defines the minimum base socket
	// of addresses that must be available. After reaching this watermark,
	// the PreAllocate and MaxAboveWatermark logic takes over to continue
	// allocating IPs.
	//
	// OBSOLETE: This field is obsolete, please use Spec.IPAM.MinAllocate
	//
	// +optional
	MinAllocate int `json:"min-allocate,omitempty"`

	// PreAllocate defines the number of IP addresses that must be
	// available for allocation in the IPAMspec. It defines the buffer of
	// addresses available immediately without requiring cilium-operator to
	// get involved.
	//
	// OBSOLETE: This field is obsolete, please use Spec.IPAM.PreAllocate
	//
	// +optional
	PreAllocate int `json:"pre-allocate,omitempty"`

	// MaxAboveWatermark is the maximum number of addresses to allocate
	// beyond the addresses needed to reach the PreAllocate watermark.
	// Going above the watermark can help reduce the number of API calls to
	// allocate IPs, e.g. when a new ENI is allocated, as many secondary
	// IPs as possible are allocated. Limiting the amount can help reduce
	// waste of IPs.
	//
	// OBSOLETE: This field is obsolete, please use Spec.IPAM.MaxAboveWatermark
	//
	// +optional
	MaxAboveWatermark int `json:"max-above-watermark,omitempty"`

	// FirstInterfaceIndex is the index of the first ENI to use for IP
	// allocation, e.g. if the node has eth0, eth1, eth2 and
	// FirstInterfaceIndex is set to 1, then only eth1 and eth2 will be
	// used for IP allocation, eth0 will be ignored for PodIP allocation.
	//
	// +optional
	FirstInterfaceIndex *int `json:"first-interface-index,omitempty"`

	// SecurityGroups is the list of security groups to attach to any ENI
	// that is created and attached to the instance.
	//
	// +optional
	SecurityGroups []string `json:"security-groups,omitempty"`

	// SecurityGroupTags is the list of tags to use when evaliating what
	// AWS security groups to use for the ENI.
	//
	// +optional
	SecurityGroupTags map[string]string `json:"security-group-tags,omitempty"`

	// SubnetTags is the list of tags to use when evaluating what AWS
	// subnets to use for ENI and IP allocation
	//
	// +optional
	SubnetTags map[string]string `json:"subnet-tags,omitempty"`

	// VpcID is the VPC ID to use when allocating ENIs
	VpcID string `json:"vpc-id,omitempty"`

	// AvailabilityZone is the availability zone to use when allocating
	// ENIs
	AvailabilityZone string `json:"availability-zone,omitempty"`

	// DeleteOnTermination defines that the ENI should be deleted when the
	// associated instance is terminated. If the parameter is not set the
	// default behavior is to delete the ENI on instance termination.
	//
	// +optional
	DeleteOnTermination *bool `json:"delete-on-termination,omitempty"`
}

// ENI represents an AWS Elastic Network Interface
//
// More details:
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html
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

	// AvailabilityZone is the availability zone of the ENI
	//
	// +optional
	AvailabilityZone string `json:"availability-zone,omitempty"`

	// Description is the description field of the ENI
	//
	// +optional
	Description string `json:"description,omitempty"`

	// Number is the interface index, it used in combination with
	// FirstInterfaceIndex
	//
	// +optional
	Number int `json:"number,omitempty"`

	// Subnet is the subnet the ENI is associated with
	//
	// +optional
	Subnet AwsSubnet `json:"subnet,omitempty"`

	// VPC is the VPC information to which the ENI is attached to
	//
	// +optional
	VPC AwsVPC `json:"vpc,omitempty"`

	// Addresses is the list of all IPs associated with the ENI, including
	// all secondary addresses
	//
	// +optional
	Addresses []string `json:"addresses,omitempty"`

	// SecurityGroups are the security groups associated with the ENI
	SecurityGroups []string `json:"security-groups,omitempty"`
}

// ENIStatus is the status of ENI addressing of the node
type ENIStatus struct {
	// ENIs is the list of ENIs on the node
	//
	// +optional
	ENIs map[string]ENI `json:"enis,omitempty"`
}

// AwsSubnet stores information regarding an AWS subnet
type AwsSubnet struct {
	// ID is the ID of the subnet
	ID string `json:"id,omitempty"`

	// CIDR is the CIDR range associated with the subnet
	CIDR string `json:"cidr,omitempty"`
}

// AwsVPC stores information regarding an AWS VPC
type AwsVPC struct {
	/// ID is the ID of a VPC
	ID string `json:"id,omitempty"`

	// PrimaryCIDR is the primary CIDR of the VPC
	PrimaryCIDR string `json:"primary-cidr,omitempty"`

	// CIDRs is the list of CIDR ranges associated with the VPC
	CIDRs []string `json:"cidrs,omitempty"`
}
