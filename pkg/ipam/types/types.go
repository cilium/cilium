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

// Limits specifies the IPAM relevant instance limits
type Limits struct {
	// Adapters specifies the maximum number of interfaces that can be
	// attached to the instance
	Adapters int

	// IPv4 is the maximum number of IPv4 addresses per adapter/interface
	IPv4 int

	// IPv6 is the maximum number of IPv6 addresses per adapter/interface
	IPv6 int
}

// AllocationIP is an IP which is available for allocation, or already
// has been allocated
type AllocationIP struct {
	// Owner is the owner of the IP. This field is set if the IP has been
	// allocated. It will be set to the pod name or another identifier
	// representing the usage of the IP
	//
	// The owner field is left blank for an entry in Spec.IPAM.Pool and
	// filled out as the IP is used and also added to Status.IPAM.Used.
	//
	// +optional
	Owner string `json:"owner,omitempty"`

	// Resource is set for both available and allocated IPs, it represents
	// what resource the IP is associated with, e.g. in combination with
	// AWS ENI, this will refer to the ID of the ENI
	//
	// +optional
	Resource string `json:"resource,omitempty"`
}

// AllocationMap is a map of allocated IPs indexed by IP
type AllocationMap map[string]AllocationIP

// IPAMSpec is the IPAM specification of the node
//
// This structure is embedded into v2.CiliumNode
type IPAMSpec struct {
	// Pool is the list of IPs available to the node for allocation. When
	// an IP is used, the IP will remain on this list but will be added to
	// Status.IPAM.Used
	//
	// +optional
	Pool AllocationMap `json:"pool,omitempty"`

	// PodCIDRs is the list of CIDRs available to the node for allocation.
	// When an IP is used, the IP will be added to Status.IPAM.Used
	//
	// +optional
	PodCIDRs []string `json:"podCIDRs,omitempty"`

	// MinAllocate is the minimum number of IPs that must be allocated when
	// the node is first bootstrapped. It defines the minimum base socket
	// of addresses that must be available. After reaching this watermark,
	// the PreAllocate and MaxAboveWatermark logic takes over to continue
	// allocating IPs.
	//
	// +optional
	MinAllocate int `json:"min-allocate,omitempty"`

	// PreAllocate defines the number of IP addresses that must be
	// available for allocation in the IPAMspec. It defines the buffer of
	// addresses available immediately without requiring cilium-operator to
	// get involved.
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
	// +optional
	MaxAboveWatermark int `json:"max-above-watermark,omitempty"`
}

// IPAMStatus is the IPAM status of a node
//
// This structure is embedded into v2.CiliumNode
type IPAMStatus struct {
	// Used lists all IPs out of Spec.IPAM.Pool which have been allocated
	// and are in use.
	//
	// +optional
	Used AllocationMap `json:"used,omitempty"`
}
