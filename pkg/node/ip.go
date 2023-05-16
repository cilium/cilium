// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"net/netip"
)

var excludedIPs []netip.Addr

// GetExcludedIPs returns a list of IPs from netdevices that Cilium
// needs to exclude to operate
func GetExcludedIPs() []netip.Addr {
	return excludedIPs
}
