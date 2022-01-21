// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package types

import (
	"fmt"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/lock"
)

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
	// +kubebuilder:validation:Minimum=0
	MinAllocate int `json:"min-allocate,omitempty"`

	// MaxAllocate is the maximum number of IPs that can be allocated to the
	// node. When the current amount of allocated IPs will approach this value,
	// the considered value for PreAllocate will decrease down to 0 in order to
	// not attempt to allocate more addresses than defined.
	//
	// +kubebuilder:validation:Minimum=0
	MaxAllocate int `json:"max-allocate,omitempty"`

	// PreAllocate defines the number of IP addresses that must be
	// available for allocation in the IPAMspec. It defines the buffer of
	// addresses available immediately without requiring cilium-operator to
	// get involved.
	//
	// +kubebuilder:validation:Minimum=0
	PreAllocate int `json:"pre-allocate,omitempty"`

	// MaxAboveWatermark is the maximum number of addresses to allocate
	// beyond the addresses needed to reach the PreAllocate watermark.
	// Going above the watermark can help reduce the number of API calls to
	// allocate IPs, e.g. when a new ENI is allocated, as many secondary
	// IPs as possible are allocated. Limiting the amount can help reduce
	// waste of IPs.
	//
	// +kubebuilder:validation:Minimum=0
	MaxAboveWatermark int `json:"max-above-watermark,omitempty"`
}

// IPReleaseStatus  defines the valid states in IP release handshake
//
// +kubebuilder:validation:Enum=marked-for-release;ready-for-release;do-not-release;released
type IPReleaseStatus string

// IPAMStatus is the IPAM status of a node
//
// This structure is embedded into v2.CiliumNode
type IPAMStatus struct {
	// Used lists all IPs out of Spec.IPAM.Pool which have been allocated
	// and are in use.
	//
	// +optional
	Used AllocationMap `json:"used,omitempty"`

	// Operator is the Operator status of the node
	//
	// +optional
	OperatorStatus OperatorStatus `json:"operator-status,omitempty"`

	// ReleaseIPs tracks the state for every IP considered for release.
	// value can be one of the following string :
	// * marked-for-release : Set by operator as possible candidate for IP
	// * ready-for-release  : Acknowledged as safe to release by agent
	// * do-not-release     : IP already in use / not owned by the node. Set by agent
	// * released           : IP successfully released. Set by operator
	//
	// +optional
	ReleaseIPs map[string]IPReleaseStatus `json:"release-ips,omitempty"`
}

// OperatorStatus is the status used by cilium-operator to report
// errors in case the allocation CIDR failed.
type OperatorStatus struct {
	// Error is the error message set by cilium-operator.
	//
	// +optional
	Error string `json:"error,omitempty"`
}

// Tags implements generic key value tags
type Tags map[string]string

// Match returns true if the required tags are all found
func (t Tags) Match(required Tags) bool {
	for k, neededvalue := range required {
		haveValue, ok := t[k]
		if !ok || (ok && neededvalue != haveValue) {
			return false
		}
	}
	return true
}

// Subnet is a representation of a subnet
type Subnet struct {
	// ID is the subnet ID
	ID string

	// Name is the subnet name
	Name string

	// CIDR is the CIDR associated with the subnet
	CIDR *cidr.CIDR

	// AvailabilityZone is the availability zone of the subnet
	AvailabilityZone string

	// VirtualNetworkID is the virtual network the subnet is in
	VirtualNetworkID string

	// AvailableAddresses is the number of addresses available for
	// allocation
	AvailableAddresses int

	// Tags is the tags of the subnet
	Tags Tags
}

// SubnetMap indexes subnets by subnet ID
type SubnetMap map[string]*Subnet

// FirstSubnetWithAvailableAddresses returns the first pool ID in the list of
// subnets with available addresses. If any of the preferred pool IDs have
// available addresses, the first pool ID with available addresses is returned.
func (m SubnetMap) FirstSubnetWithAvailableAddresses(preferredPoolIDs []PoolID) (PoolID, int) {
	for _, p := range preferredPoolIDs {
		if s := m[string(p)]; s != nil {
			if s.AvailableAddresses > 0 {
				return p, s.AvailableAddresses
			}
		}
	}

	for poolID, s := range m {
		if s.AvailableAddresses > 0 {
			return PoolID(poolID), s.AvailableAddresses
		}
	}

	return PoolNotExists, 0
}

// VirtualNetwork is the representation of a virtual network
type VirtualNetwork struct {
	// ID is the ID of the virtual network
	ID string

	// PrimaryCIDR is the primary IPv4 CIDR
	PrimaryCIDR string

	// CIDRs is the list of secondary IPv4 CIDR ranges associated with the VPC
	CIDRs []string
}

// VirtualNetworkMap indexes virtual networks by their ID
type VirtualNetworkMap map[string]*VirtualNetwork

// PoolNotExists indicate that no such pool ID exists
const PoolNotExists = PoolID("")

// PoolUnspec indicates that the pool ID is unspecified
const PoolUnspec = PoolNotExists

// PoolID is the type used to identify an IPAM pool
type PoolID string

// PoolQuota defines the limits of an IPAM pool
type PoolQuota struct {
	// AvailabilityZone is the availability zone in which the IPAM pool resides in
	AvailabilityZone string

	// AvailableIPs is the number of available IPs in the pool
	AvailableIPs int
}

// PoolQuotaMap is a map of pool quotas indexes by pool identifier
type PoolQuotaMap map[PoolID]PoolQuota

// Interface is the implementation of a IPAM relevant network interface
// +k8s:deepcopy-gen=false
// +deepequal-gen=false
type Interface interface {
	// InterfaceID must return the identifier of the interface
	InterfaceID() string

	// ForeachAddress must iterate over all addresses of the interface and
	// call fn for each address
	ForeachAddress(instanceID string, fn AddressIterator) error
}

// InterfaceRevision is the configurationr revision of a network interface. It
// consists of a revision hash representing the current configuration version
// and the resource itself.
//
// +k8s:deepcopy-gen=false
// +deepequal-gen=false
type InterfaceRevision struct {
	// Resource is the interface resource
	Resource Interface

	// Fingerprint is the fingerprint reprsenting the network interface
	// configuration. It is typically implemented as the result of a hash
	// function calculated off the resource. This field is optional, not
	// all IPAM backends make use of fingerprints.
	Fingerprint string
}

// Instance is the representation of an instance, typically a VM, subject to
// per-node IPAM logic
//
// +k8s:deepcopy-gen=false
// +deepequal-gen=false
type Instance struct {
	// interfaces is a map of all interfaces attached to the instance
	// indexed by the interface ID
	Interfaces map[string]InterfaceRevision
}

// InstanceMap is the list of all instances indexed by instance ID
//
// +k8s:deepcopy-gen=false
// +deepequal-gen=false
type InstanceMap struct {
	mutex lock.RWMutex
	data  map[string]*Instance
}

// NewInstanceMap returns a new InstanceMap
func NewInstanceMap() *InstanceMap {
	return &InstanceMap{data: map[string]*Instance{}}
}

// Update updates the definition of an interface for a particular instance. If
// the interface is already known, the definition is updated, otherwise the
// interface is added to the instance.
func (m *InstanceMap) Update(instanceID string, iface InterfaceRevision) {
	m.mutex.Lock()
	m.updateLocked(instanceID, iface)
	m.mutex.Unlock()
}

func (m *InstanceMap) updateLocked(instanceID string, iface InterfaceRevision) {
	if iface.Resource == nil {
		return
	}

	i, ok := m.data[instanceID]
	if !ok {
		i = &Instance{}
		m.data[instanceID] = i
	}

	if i.Interfaces == nil {
		i.Interfaces = map[string]InterfaceRevision{}
	}

	i.Interfaces[iface.Resource.InterfaceID()] = iface
}

type Address interface{}

// AddressIterator is the function called by the ForeachAddress iterator
type AddressIterator func(instanceID, interfaceID, ip, poolID string, address Address) error

func foreachAddress(instanceID string, instance *Instance, fn AddressIterator) error {
	for _, rev := range instance.Interfaces {
		if err := rev.Resource.ForeachAddress(instanceID, fn); err != nil {
			return err
		}
	}

	return nil
}

// ForeachAddress calls fn for each address on each interface attached to each
// instance. If an instanceID is specified, the only the interfaces and
// addresses of the specified instance are considered.
//
// The InstanceMap is read-locked throughout the iteration process, i.e., no
// updates will occur. However, the address object given to the AddressIterator
// will point to live data and must be deep copied if used outside of the
// context of the iterator function.
func (m *InstanceMap) ForeachAddress(instanceID string, fn AddressIterator) error {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if instanceID != "" {
		if instance := m.data[instanceID]; instance != nil {
			return foreachAddress(instanceID, instance, fn)
		}
		return fmt.Errorf("instance does not exist")
	}

	for instanceID, instance := range m.data {
		if err := foreachAddress(instanceID, instance, fn); err != nil {
			return err
		}
	}

	return nil
}

// InterfaceIterator is the function called by the ForeachInterface iterator
type InterfaceIterator func(instanceID, interfaceID string, iface InterfaceRevision) error

func foreachInterface(instanceID string, instance *Instance, fn InterfaceIterator) error {
	for _, rev := range instance.Interfaces {
		if err := fn(instanceID, rev.Resource.InterfaceID(), rev); err != nil {
			return err
		}
	}

	return nil
}

// ForeachInterface calls fn for each interface on each interface attached to
// each instance. If an instanceID is specified, the only the interfaces and
// addresses of the specified instance are considered.
//
// The InstanceMap is read-locked throughout the iteration process, i.e., no
// updates will occur. However, the address object given to the InterfaceIterator
// will point to live data and must be deep copied if used outside of the
// context of the iterator function.
func (m *InstanceMap) ForeachInterface(instanceID string, fn InterfaceIterator) error {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if instanceID != "" {
		if instance := m.data[instanceID]; instance != nil {
			return foreachInterface(instanceID, instance, fn)
		}
		return fmt.Errorf("instance does not exist")
	}
	for instanceID, instance := range m.data {
		if err := foreachInterface(instanceID, instance, fn); err != nil {
			return err
		}
	}

	return nil
}

// GetInterface returns returns a particular interface of an instance. The
// boolean indicates whether the interface was found or not.
func (m *InstanceMap) GetInterface(instanceID, interfaceID string) (InterfaceRevision, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if instance := m.data[instanceID]; instance != nil {
		if rev, ok := instance.Interfaces[interfaceID]; ok {
			return rev, true
		}
	}

	return InterfaceRevision{}, false
}

// DeepCopy returns a deep copy
func (m *InstanceMap) DeepCopy() *InstanceMap {
	c := NewInstanceMap()
	m.ForeachInterface("", func(instanceID, interfaceID string, rev InterfaceRevision) error {
		// c is not exposed yet, we can access it without locking it
		c.updateLocked(instanceID, rev)
		return nil
	})
	return c
}

// NumInstances returns the number of instances in the instance map
func (m *InstanceMap) NumInstances() (size int) {
	m.mutex.RLock()
	size = len(m.data)
	m.mutex.RUnlock()
	return
}
