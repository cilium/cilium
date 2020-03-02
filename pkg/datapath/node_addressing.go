// Copyright 2018-2020 Authors of Cilium
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

package datapath

import (
	"net"

	"github.com/cilium/cilium/pkg/cidr"
)

// NodeAddressingFamily is the node addressing information for a particular
// address family
type NodeAddressingFamily interface {
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

	// LocalAddresses lists all local addresses
	LocalAddresses() ([]net.IP, error)

	// LoadBalancerNodeAddresses lists all addresses on which HostPort and
	// NodePort services should be responded to
	LoadBalancerNodeAddresses() []net.IP
}

// NodeAddressing implements addressing of a node
type NodeAddressing interface {
	IPv6() NodeAddressingFamily
	IPv4() NodeAddressingFamily
}
