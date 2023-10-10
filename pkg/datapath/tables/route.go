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
		FromKey: func(id RouteID) []byte {
			return id.Key()
		},
		Unique: true,
	}

	RouteLinkIndex = statedb.Index[*Route, int]{
		Name: "LinkIndex",
		FromObject: func(r *Route) index.KeySet {
			return index.NewKeySet(index.Int(r.LinkIndex))
		},
		FromKey: func(linkIndex int) []byte {
			return index.Int(linkIndex)
		},
	}

	RouteTableCell = statedb.NewProtectedTableCell[*Route](
		"routes",
		RouteIDIndex,
		RouteLinkIndex,
	)
)

type RouteID struct {
	Table     int
	LinkIndex int
	Dst       netip.Prefix
}

func (id RouteID) Key() []byte {
	key := append(index.Uint64(uint64(id.Table)), '+')
	key = append(key, index.Uint64(uint64(id.Table))...)
	key = append(key, '+')
	key = append(key, index.NetIPPrefix(id.Dst)...)
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
