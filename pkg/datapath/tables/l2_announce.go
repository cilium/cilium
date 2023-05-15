// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"net"

	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/statedb"

	"github.com/hashicorp/go-memdb"
	"golang.org/x/exp/slices"
)

type L2AnnounceEntry struct {
	// IP and network interface are the primary key of this entry
	IP               net.IP
	NetworkInterface string

	// The key of the services for which this proxy entry was added
	Origins []resource.Key

	Deleted  bool
	Revision uint64
}

func (pne *L2AnnounceEntry) DeepCopy() *L2AnnounceEntry {
	var n L2AnnounceEntry
	// Shallow copy
	n = *pne
	// Explicit clone for slices
	n.IP = slices.Clone(pne.IP)
	n.Origins = slices.Clone(pne.Origins)
	return &n
}

var L2AnnouncementTableCell = statedb.NewTableCell[*L2AnnounceEntry](schema)

func ByProxyIPAndInterface(ip net.IP, iface string) statedb.Query {
	return statedb.Query{
		Index: idIndex,
		Args:  []any{ip, iface},
	}
}

func ByProxyOrigin(originKey resource.Key) statedb.Query {
	return statedb.Query{
		Index: originIndex,
		Args:  []any{originKey},
	}
}

var (
	idIndex     = statedb.Index("id")
	originIndex = statedb.Index("byOrigin")
	schema      = &memdb.TableSchema{
		Name: "l2-announce-entries",
		Indexes: map[string]*memdb.IndexSchema{
			string(idIndex): {
				Name:   string(idIndex),
				Unique: true,
				Indexer: &memdb.CompoundIndex{
					Indexes: []memdb.Indexer{
						&statedb.IPIndexer{Field: "IP"},
						&memdb.StringFieldIndex{Field: "NetworkInterface"},
					},
				},
			},
			string(originIndex): {
				Name:         string(originIndex),
				AllowMissing: true,
				Unique:       false,
				Indexer:      &statedb.StringerSliceFieldIndex{Field: "Origins"},
			},
			statedb.RevisionIndexSchema.Name: statedb.RevisionIndexSchema,
		},
	}
)
