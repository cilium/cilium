// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stats

// InterfaceStats contains stats about the current state of an individual IPAM node.
// This is used while performing a resync to determine if the node is able to
// allocate more addresses.
type InterfaceStats struct {
	// NodeCapacity is the current inferred total capacity for a Node to schedule
	// IPv4 addresses.
	//
	// This does not account for currently used addresses.
	NodeCapacity int

	// RemainingAvailableInterfaceCount is the number of interfaces currently available
	// for IPv4 address allocation.
	RemainingAvailableInterfaceCount int

	// NodeIPv6Capacity is the current inferred total capacity for a Node to schedule
	// IPv6 addresses.
	//
	// This does not account for currently used addresses.
	NodeIPv6Capacity int

	// RemainingAvailableIPv6InterfaceCount is the number of interfaces currently available
	// for IPv6 address allocation.
	RemainingAvailableIPv6InterfaceCount int

	// AssignedStaticIP is the static IP address assigned to the node (ex: public Elastic IP address in AWS)
	AssignedStaticIP string
}
