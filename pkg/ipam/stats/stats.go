// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stats

// InterfaceStats contains stats about the current state of an individual IPAM node.
// This is used while performing a resync to determine if the node is able to
// allocate more addresses.
type InterfaceStats struct {
	// NodeCapacity is the current inferred total capacity for a Node to schedule
	// addresses.
	//
	// This does not account for currently used addresses.
	NodeCapacity int

	// RemainingAvailableInterfaceCount is the number of interfaces currently available.
	RemainingAvailableInterfaceCount int
}
