// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"net/netip"
	"slices"

	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
)

type L2AnnounceKey struct {
	// IP and network interface are the primary key of this entry
	IP               netip.Addr
	NetworkInterface string
}

func (k L2AnnounceKey) Key() []byte {
	key := append(index.NetIPAddr(k.IP), '+')
	key = append(key, index.String(k.NetworkInterface)...)
	return key
}

type L2AnnounceEntry struct {
	L2AnnounceKey

	// The key of the services for which this proxy entry was added
	Origins []resource.Key
}

func (pne *L2AnnounceEntry) DeepCopy() *L2AnnounceEntry {
	// Shallow copy
	var n L2AnnounceEntry = *pne
	// Explicit clone for slices
	n.Origins = slices.Clone(pne.Origins)
	return &n
}

var (
	L2AnnounceIDIndex = statedb.Index[*L2AnnounceEntry, L2AnnounceKey]{
		Name: "id",
		FromObject: func(b *L2AnnounceEntry) index.KeySet {
			return index.NewKeySet(b.Key())
		},
		FromKey: func(id L2AnnounceKey) []byte {
			return id.Key()
		},
		Unique: true,
	}

	L2AnnounceOriginIndex = statedb.Index[*L2AnnounceEntry, resource.Key]{
		Name: "origin",
		FromObject: func(b *L2AnnounceEntry) index.KeySet {
			return index.StringerSlice(b.Origins)
		},
		FromKey: func(id resource.Key) []byte {
			return index.Stringer(id)
		},
	}
)

func NewL2AnnounceTable() statedb.RWTable[*L2AnnounceEntry] {
	return statedb.NewTable[*L2AnnounceEntry](
		"l2-announce",
		L2AnnounceIDIndex,
		L2AnnounceOriginIndex,
	)
}

func (*L2AnnounceEntry) TableHeader() []string {
	return []string{
		"IP",
		"NetworkInterface",
	}
}

func (e *L2AnnounceEntry) TableRow() []string {
	return []string{
		e.IP.String(),
		e.NetworkInterface,
	}
}
