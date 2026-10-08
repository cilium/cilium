// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import "net"

var excludedIPs []net.IP

// GetExcludedIPs returns a list of IPs from netdevices that Cilium
// needs to exclude to operate
func GetExcludedIPs() []net.IP {
	return excludedIPs
}
