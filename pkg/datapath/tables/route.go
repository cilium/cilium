// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"fmt"
	"net/netip"

	"github.com/hashicorp/go-memdb"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/statedb"
)

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

const (
	linkIndexIndex statedb.Index = "LinkIndex"
)

var (
	routeTableSchema = &memdb.TableSchema{
		Name: "routes",
		Indexes: map[string]*memdb.IndexSchema{
			"id": {
				Name:         "id",
				AllowMissing: false,
				Unique:       true,
				Indexer: &memdb.CompoundIndex{
					Indexes: []memdb.Indexer{
						&memdb.IntFieldIndex{Field: "Table"},
						&memdb.IntFieldIndex{Field: "LinkIndex"},
						&statedb.NetIPPrefixFieldIndex{Field: "Dst"},
					},
				},
			},
			string(linkIndexIndex): {
				Name:         string(linkIndexIndex),
				AllowMissing: false,
				Unique:       false,
				Indexer:      &memdb.IntFieldIndex{Field: "LinkIndex"},
			}},
	}
)

func RouteByLinkIndex(index int) statedb.Query {
	return statedb.Query{Index: linkIndexIndex, Args: []any{index}}
}

func HasDefaultRoute(reader statedb.TableReader[*Route], linkIndex int) bool {
	// Device has a default route when a route exists in the main table
	// with a zero destination.
	for _, prefix := range []netip.Prefix{zeroPrefixV4, zeroPrefixV6} {
		q := statedb.Query{
			Index: "id",
			Args: []any{
				unix.RT_TABLE_MAIN,
				linkIndex,
				prefix,
			},
		}
		r, err := reader.First(q)
		if err != nil {
			panic(fmt.Sprintf("Internal error: Query %+v is malformed (%s)", q, err))
		}
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
