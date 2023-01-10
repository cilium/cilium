// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"net"
)

// Contains method is used to check if a particular IP is blacklisted or not.
func (blacklist *IPBlacklist) Contains(ip net.IP) bool {
	if _, ok := blacklist.ips[ip.String()]; ok {
		return true
	}

	return false
}
