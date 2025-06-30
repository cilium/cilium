// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mtu

import (
	"net/netip"
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
)

var (
	MTURouteIndex = statedb.Index[RouteMTU, netip.Prefix]{
		Name: "cidr",
		FromObject: func(rm RouteMTU) index.KeySet {
			return index.NewKeySet(index.NetIPPrefix(rm.Prefix))
		},
		FromKey:    index.NetIPPrefix,
		FromString: index.NetIPPrefixString,
		Unique:     true,
	}
)

func NewMTUTable() (statedb.RWTable[RouteMTU], error) {
	return statedb.NewTable(
		"mtu",
		MTURouteIndex,
	)
}

var DefaultPrefixV4 = netip.MustParsePrefix("0.0.0.0/0")
var DefaultPrefixV6 = netip.MustParsePrefix("::/0")

type RouteMTU struct {
	Prefix              netip.Prefix
	DeviceMTU           int
	RouteMTU            int
	RoutePostEncryptMTU int
}

func (RouteMTU) TableHeader() []string {
	return []string{"Prefix", "DeviceMTU", "RouteMTU", "RoutePostEncryptMTU"}
}

func (r RouteMTU) TableRow() []string {
	return []string{
		r.Prefix.String(),
		strconv.Itoa(r.DeviceMTU),
		strconv.Itoa(r.RouteMTU),
		strconv.Itoa(r.RoutePostEncryptMTU),
	}
}
