// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"errors"
	"sync"

	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/netns"
)

var Cell = cell.Module(
	"loadbalancer",
	"Experimental load-balancing control-plane",

	cell.Config(loadbalancer.DefaultConfig),
	cell.Provide(loadbalancer.NewExternalConfig),

	// Replace the [k8s.ServiceCacheReader] and [service.ServiceReader] if this
	// implementation is enabled.
	cell.Provide(newAdapters),
	cell.DecorateAll(decorateAdapters),

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
