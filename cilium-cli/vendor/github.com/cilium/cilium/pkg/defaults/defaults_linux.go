// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package defaults

import (
	"github.com/vishvananda/netlink"
)

const (
	// AddressScopeMax controls the maximum address scope for addresses to be
	// considered local ones with HOST_ID in the ipcache
	AddressScopeMax = int(netlink.SCOPE_LINK) - 1
)
