// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
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
	return statedb.NewTable(
		"routes",
		RouteIDIndex,
		RouteLinkIndex,
	)
}

type RouteID struct {
	Table     RouteTable
	LinkIndex int
	Dst       netip.Prefix
}

func (id RouteID) Key() index.Key {
	key := make([]byte, 0, 4 /* table */ +4 /* link */ +17 /* prefix & bits */)
	key = binary.BigEndian.AppendUint32(key, uint32(id.Table))
	key = binary.BigEndian.AppendUint32(key, uint32(id.LinkIndex))
	addrBytes := id.Dst.Addr().As16()
	key = append(key, addrBytes[:]...)
	return append(key, uint8(id.Dst.Bits()))
}

type Route struct {
	Table     RouteTable
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
		r, _, _ := tbl.Get(rxn, RouteIDIndex.Query(RouteID{
			RT_TABLE_MAIN,
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

type (
	RouteScope uint8
	RouteTable uint32
)

// Definitions for route scopes and tables. These are repeated here from the unix
// package to keep the tables package buildable on non-Linux platforms.
const (
	RT_SCOPE_UNIVERSE = RouteScope(0x0)
	RT_SCOPE_SITE     = RouteScope(0xc8)
	RT_SCOPE_LINK     = RouteScope(0xfd)
	RT_SCOPE_HOST     = RouteScope(0xfe)
	RT_SCOPE_NOWHERE  = RouteScope(0xff)
	RT_TABLE_UNSPEC   = RouteTable(0x0)
	RT_TABLE_COMPAT   = RouteTable(0xfc)
	RT_TABLE_DEFAULT  = RouteTable(0xfd)
	RT_TABLE_MAIN     = RouteTable(0xfe)
	RT_TABLE_LOCAL    = RouteTable(0xff)
	RT_TABLE_MAX      = RouteTable(0xffffffff)
)
