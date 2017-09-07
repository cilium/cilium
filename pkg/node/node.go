// Copyright 2016-2017 Authors of Cilium
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

package node

import (
	"net"

	"k8s.io/client-go/pkg/api/v1"
)

// Identity represents the node identity of a node.
type Identity struct {
	Name string
}

// String returns the string representation on NodeIdentity.
func (nn Identity) String() string {
	return nn.Name
}

// Node contains the nodes name, the list of addresses to this address
type Node struct {
	Name        string
	IPAddresses []Address

	// IPv4AllocCIDR if set, is the IPv4 address pool out of which the node
	// allocates IPs for local endpoints from
	IPv4AllocCIDR *net.IPNet

	// IPv6AllocCIDR if set, is the IPv6 address pool out of which the node
	// allocates IPs for local endpoints from
	IPv6AllocCIDR *net.IPNet

	// dev contains the device name to where the IPv6 traffic should be send
	dev string
}

// Address is a node address which contains an IP and the address type.
type Address struct {
	AddressType v1.NodeAddressType
	IP          net.IP
}

// GetNodeIP returns one of the node's IP addresses available with the
// following priority:
// - NodeInternalIP
// - NodeExternalIP
// - other IP address type
func (n *Node) GetNodeIP(ipv6 bool) net.IP {
	var backupIP net.IP
	for _, addr := range n.IPAddresses {
		if (ipv6 && addr.IP.To4() != nil) ||
			(!ipv6 && addr.IP.To4() == nil) {
			continue
		}
		switch addr.AddressType {
		// Always prefer a cluster internal IP
		case v1.NodeInternalIP:
			return addr.IP
		case v1.NodeExternalIP:
			// Fall back to external Node IP
			// if no internal IP could be found
			backupIP = addr.IP
		default:
			// As a last resort, if no internal or external
			// IP was found, use any node address available
			if backupIP == nil {
				backupIP = addr.IP
			}
		}
	}
	return backupIP
}
