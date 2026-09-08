// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package addressing

import (
	"net/netip"
)

// AddressType represents a type of IP address for a node. They are copied
// from k8s.io/api/core/v1/types.go to avoid pulling in a lot of Kubernetes
// imports into this package.
type AddressType string

const (
	NodeHostName         AddressType = "Hostname"
	NodeExternalIP       AddressType = "ExternalIP"
	NodeInternalIP       AddressType = "InternalIP"
	NodeExternalDNS      AddressType = "ExternalDNS"
	NodeInternalDNS      AddressType = "InternalDNS"
	NodeCiliumInternalIP AddressType = "CiliumInternalIP"
)

type Address interface {
	AddrType() AddressType
	// Addr returns the address, or the zero value if it does not hold a
	// valid IP address.
	Addr() netip.Addr
}

// ExtractNodeIP returns one of the provided IP addresses available with the following priority:
// - NodeInternalIP
// - NodeExternalIP
// - other IP address type
// The zero value is returned if ExtractNodeIP fails to get an IP based on the provided address family.
func ExtractNodeIP[T Address](addrs []T, ipv6 bool) netip.Addr {
	var backupIP netip.Addr
	for _, addr := range addrs {
		parsed := addr.Addr()
		if !parsed.IsValid() {
			continue
		}
		if ipv6 == parsed.Is4() {
			continue
		}
		switch addr.AddrType() {
		// Ignore CiliumInternalIPs
		case NodeCiliumInternalIP:
			continue
		// Always prefer a cluster internal IP
		case NodeInternalIP:
			return parsed
		case NodeExternalIP:
			// Fall back to external Node IP
			// if no internal IP could be found
			backupIP = parsed
		default:
			// As a last resort, if no internal or external
			// IP was found, use any node address available
			if !backupIP.IsValid() {
				backupIP = parsed
			}
		}
	}
	return backupIP
}
