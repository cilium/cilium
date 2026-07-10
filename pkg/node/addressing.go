// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"net"

	"github.com/cilium/cilium/pkg/cidr"
)

// AddressingFamily is the node addressing information for a particular address
// family
type AddressingFamily interface {
	// Router is the address that will act as the router on each node where
	// an agent is running on. Endpoints have a default route that points
	// to this address.
	Router() net.IP

	// PrimaryExternal is the primary external address of the node. Nodes
	// must be able to reach each other via this address.
	PrimaryExternal() net.IP

	// AllocationCIDR is the CIDR used for IP allocation of all endpoints
	// on the node
	AllocationCIDR() *cidr.CIDR
}

// Addressing implements addressing of a node
type Addressing interface {
	IPv6() AddressingFamily
	IPv4() AddressingFamily
}
