// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflectors

import (
	"errors"
	"sync"

	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/netns"
)

var Cell = cell.Module(
	"loadbalancer-reflectors",
	"Reflects external state to load-balancing tables",

	// Reflects Kubernetes Services and Endpoint(Slices) to load-balancing tables
	K8sReflectorCell,

	// Reflects state to load-balancing tables from a local file specified with
	// '--lb-state-file'.
	FileReflectorCell,

	// Provide [HaveNetNSCookieSupport] to probe for netns cookie support.
	// This is provided from as the [K8sReflectorCell] requires it. This way
	// test code that wants to use the reflector doesn't need to depend on
	// anything else.
	cell.Provide(NetnsCookieSupportFunc),
)

type HaveNetNSCookieSupport func() bool

func NetnsCookieSupportFunc() HaveNetNSCookieSupport {
	return sync.OnceValue(func() bool {
		_, err := netns.GetNetNSCookie()
		return !errors.Is(err, unix.ENOPROTOOPT)
	})
}
