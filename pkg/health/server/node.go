// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"github.com/cilium/cilium/api/v1/models"
)

type healthNode struct {
	*models.NodeElement
	preferPrimaryIPv6 bool
}

// NewHealthNode creates a new node structure based on the specified model.
func NewHealthNode(elem *models.NodeElement, preferPrimaryIPv6 bool) healthNode {
	return healthNode{
		NodeElement:       elem,
		preferPrimaryIPv6: preferPrimaryIPv6,
	}
}

// preferAddr returns the IP from the preferred address family, falling back
// to the other if the preferred one is not enabled.
func preferAddr(preferIPv6 bool, ipv4, ipv6 *models.NodeAddressingElement) string {
	primary, secondary := ipv4, ipv6
	if preferIPv6 {
		primary, secondary = ipv6, ipv4
	}
	if primary.Enabled {
		return primary.IP
	}
	return secondary.IP
}

// PrimaryIP returns the primary IP address of the node. When
// preferPrimaryIPv6 is set, IPv6 is preferred over IPv4.
func (n *healthNode) PrimaryIP() string {
	return preferAddr(n.preferPrimaryIPv6, n.PrimaryAddress.IPv4, n.PrimaryAddress.IPv6)
}

// SecondaryIPs return a list of IP addresses corresponding to secondary addresses
// of the node. If both IPv4 and IPv6 are enabled then the non-primary address
// family is also returned in the list.
func (n *healthNode) SecondaryIPs() []string {
	var addresses []string

	if n.PrimaryAddress.IPv4.Enabled && n.PrimaryAddress.IPv6.Enabled {
		if n.preferPrimaryIPv6 {
			addresses = append(addresses, n.PrimaryAddress.IPv4.IP)
		} else {
			addresses = append(addresses, n.PrimaryAddress.IPv6.IP)
		}
	}

	for _, addr := range n.SecondaryAddresses {
		if addr.Enabled {
			addresses = append(addresses, addr.IP)
		}
	}

	return addresses
}

// HealthIP returns the IP address of the health endpoint for the node.
// When preferPrimaryIPv6 is set, IPv6 is preferred over IPv4.
func (n *healthNode) HealthIP() string {
	if n.HealthEndpointAddress == nil {
		return ""
	}
	return preferAddr(n.preferPrimaryIPv6, n.HealthEndpointAddress.IPv4, n.HealthEndpointAddress.IPv6)
}

// SecondaryHealthIPs return a list of IP addresses corresponding to secondary
// addresses of the health endpoint. In the current implementation, this
// is the non-primary address family IP if both IPv4 and IPv6 are enabled.
func (n *healthNode) SecondaryHealthIPs() []string {
	if n.HealthEndpointAddress == nil {
		return nil
	}

	if n.HealthEndpointAddress.IPv4.Enabled && n.HealthEndpointAddress.IPv6.Enabled {
		if n.preferPrimaryIPv6 {
			return []string{n.HealthEndpointAddress.IPv4.IP}
		}
		return []string{n.HealthEndpointAddress.IPv6.IP}
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
