// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ip

import (
	"strconv"

	"github.com/vishvananda/netlink"
)

func ParseScope(scope string) (int, error) {
	switch scope {
	case "global":
		return int(netlink.SCOPE_UNIVERSE), nil
	case "nowhere":
		return int(netlink.SCOPE_NOWHERE), nil
	case "host":
		return int(netlink.SCOPE_HOST), nil
	case "link":
		return int(netlink.SCOPE_LINK), nil
	case "site":
		return int(netlink.SCOPE_SITE), nil
	default:
		return strconv.Atoi(scope)
	}
}
