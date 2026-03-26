// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"github.com/cilium/cilium/api/v1/models"
)

type healthNode struct {
	*models.NodeElement
}

// NewHealthNode creates a new node structure based on the specified model.
func NewHealthNode(elem *models.NodeElement) healthNode {
	return healthNode{
		NodeElement: elem,
	}
}

// PrimaryIP returns the primary IP address of the node.
func (n *healthNode) PrimaryIP() string {
	if n.NodeElement.PrimaryAddress.IPv4.Enabled {
		return n.NodeElement.PrimaryAddress.IPv4.IP
	}
	return n.NodeElement.PrimaryAddress.IPv6.IP
}

// SecondaryIPs return a list of IP addresses corresponding to secondary addresses
// of the node. If both IPv4 and IPv6 is enabled then primary IPv6 is also
// returned in the list, since in that case we assume that IPv4 is the primary
// address of the node, see the above function PrimaryIP().
func (n *healthNode) SecondaryIPs() []string {
	var addresses []string

	if n.NodeElement.PrimaryAddress.IPv4.Enabled && n.NodeElement.PrimaryAddress.IPv6.Enabled {
		addresses = append(addresses, n.NodeElement.PrimaryAddress.IPv6.IP)
	}

	for _, addr := range n.NodeElement.SecondaryAddresses {
		if addr.Enabled {
			addresses = append(addresses, addr.IP)
		}
	}

	return addresses
}

// HealthIP returns the IP address of the health endpoint for the node.
func (n *healthNode) HealthIP() string {
	if n.NodeElement.HealthEndpointAddress == nil {
		return ""
	}
	if n.NodeElement.HealthEndpointAddress.IPv4.Enabled {
		return n.NodeElement.HealthEndpointAddress.IPv4.IP
	}
	return n.NodeElement.HealthEndpointAddress.IPv6.IP
}

// SecondaryHealthIPs return a list of IP addresses corresponding to secondary
// addresses of the health endpoint. In the current implementation, this
// is the IPv6 IP if both IPv4 and IPv6 are enabled (IPv4 remains the primary
// health IP in such a scenario)
func (n *healthNode) SecondaryHealthIPs() []string {
	if n.NodeElement.HealthEndpointAddress == nil {
		return nil
	}

	if n.NodeElement.HealthEndpointAddress.IPv4.Enabled && n.NodeElement.HealthEndpointAddress.IPv6.Enabled {
		return []string{n.NodeElement.HealthEndpointAddress.IPv6.IP}
	}

	return nil
}

// Addresses returns a map of the node's addresses -> "primary" bool
func (n *healthNode) Addresses() map[*models.NodeAddressingElement]bool {
	addresses := map[*models.NodeAddressingElement]bool{}
	if n.NodeElement.PrimaryAddress != nil {
		addr := n.NodeElement.PrimaryAddress
		addresses[addr.IPv4] = addr.IPv4.Enabled
		addresses[addr.IPv6] = addr.IPv6.Enabled
	}
	if n.NodeElement.HealthEndpointAddress != nil {
		addresses[n.NodeElement.HealthEndpointAddress.IPv4] = false
		addresses[n.NodeElement.HealthEndpointAddress.IPv6] = false
	}
	for _, elem := range n.NodeElement.SecondaryAddresses {
		addresses[elem] = false
	}
	return addresses
}
