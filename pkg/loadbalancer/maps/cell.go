// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"errors"
	"sync"

	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/netns"
)

// Provides [LBMap] a wrapper around the load-balancing BPF maps
var Cell = cell.Module(
	"loadbalancer-maps",
	"Load-balancing BPF maps",

	// Provide [lbmaps], abstraction for the load-balancing BPF map access.
	cell.Provide(newLBMaps),

	// Provide the 'lb/' script commands for debugging and testing.
	cell.Provide(scriptCommands),

	// Provide [HaveNetNSCookieSupport] to probe for netns cookie support.
	cell.Provide(NetnsCookieSupportFunc),
)

type HaveNetNSCookieSupport func() bool

func NetnsCookieSupportFunc() HaveNetNSCookieSupport {
	return sync.OnceValue(func() bool {
		_, err := netns.GetNetNSCookie()
		return !errors.Is(err, unix.ENOPROTOOPT)
	})
}
