// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package route

import (
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

type Route struct {
	Prefix   net.IPNet
	Nexthop  *net.IP
	Local    net.IP
	Device   string
	MTU      int
	Priority int
	Proto    int
	Scope    netlink.Scope
	Table    int
	Type     int
}

// LogAttrs returns the route attributes as slog attributes.
// The return type is []any to match with signature of With().
func (r *Route) LogAttrs() []any {
	nexthop := "<nil>"
	if r.Nexthop != nil {
		nexthop = r.Nexthop.String()
	}

	return []any{
		slog.String(logfields.Prefix, r.Prefix.String()),
		slog.String(logfields.NextHop, nexthop),
		slog.String(logfields.LocalIP, r.Local.String()),
		slog.String(logfields.Interface, r.Device),
	}
}

// ByMask is used to sort an array of routes by mask, narrow first.
type ByMask []Route

func (a ByMask) Len() int {
	return len(a)
}

func (a ByMask) Less(i, j int) bool {
	lenA, _ := a[i].Prefix.Mask.Size()
	lenB, _ := a[j].Prefix.Mask.Size()
	return lenA > lenB
}

func (a ByMask) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
