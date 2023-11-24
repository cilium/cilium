// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"

	"golang.org/x/sys/unix"
)

var (
	RouteIDIndex = statedb.Index[*Route, RouteID]{
		Name: "id",
		FromObject: func(r *Route) index.KeySet {
			return index.NewKeySet(
				RouteID{
					Table:     r.Table,
					LinkIndex: r.LinkIndex,
					Dst:       r.Dst,
				}.Key(),
			)
		},
		FromKey: RouteID.Key,
		Unique:  true,
	}

	RouteLinkIndex = statedb.Index[*Route, int]{
		Name: "LinkIndex",
		FromObject: func(r *Route) index.KeySet {
			return index.NewKeySet(index.Int(r.LinkIndex))
		},
		FromKey: index.Int,
	}
)

func NewRouteTable() (statedb.RWTable[*Route], error) {
	return statedb.NewTable[*Route](
		"routes",
		RouteIDIndex,
		RouteLinkIndex,
	)
}

type RouteID struct {
	Table     int
	LinkIndex int
	Dst       netip.Prefix
}

func (id RouteID) Key() index.Key {
	key := append(index.Uint64(uint64(id.Table)), '+')
	key = append(key, index.Uint64(uint64(id.Table))...)
	key = append(key, '+')
	key = append(key, index.NetIPPrefix(id.Dst)...)
	key = append(key, 0 /* termination */)
	return key
}

type Route struct {
	Table     int
	LinkIndex int

	Scope uint8
	Dst   netip.Prefix
	Src   netip.Addr
	Gw    netip.Addr
}

func (r *Route) DeepCopy() *Route {
	r2 := *r
	return &r2
}

func (r *Route) String() string {
	return fmt.Sprintf("Route{Dst: %s, Src: %s, Table: %d, LinkIndex: %d}",
		r.Dst, r.Src, r.Table, r.LinkIndex)
}

func (*Route) TableHeader() []string {
	return []string{
		"Destination",
		"Source",
		"Gateway",
		"LinkIndex",
		"Table",
		"Scope",
	}
}

func (r *Route) TableRow() []string {
	// Addr.String() shows "invalid IP" for zero value, but here
	// we're expecting absence of IPs, so return empty string for
	// invalid IPs.
	showAddr := func(addr netip.Addr) string {
		if !addr.IsValid() {
			return ""
		}
		return addr.String()
	}
	return []string{
		r.Dst.String(),
		showAddr(r.Src),
		showAddr(r.Gw),
		fmt.Sprintf("%d", r.LinkIndex),
		fmt.Sprintf("%d", r.Table),
		fmt.Sprintf("%d", r.Scope),
	}
}

func HasDefaultRoute(tbl statedb.Table[*Route], rxn statedb.ReadTxn, linkIndex int) bool {
	// Device has a default route when a route exists in the main table
	// with a zero destination.
	for _, prefix := range []netip.Prefix{zeroPrefixV4, zeroPrefixV6} {
		r, _, _ := tbl.First(rxn, RouteIDIndex.Query(RouteID{
			unix.RT_TABLE_MAIN,
			linkIndex,
			prefix,
		}))
		if r != nil {
			return true
		}
	}
	return false
}

var (
	zeroPrefixV4 = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	zeroPrefixV6 = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
)
