// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/statedb2"
	"github.com/cilium/cilium/pkg/statedb2/index"

	"golang.org/x/exp/slices"
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
	L2AnnounceIDIndex = statedb2.Index[*L2AnnounceEntry, L2AnnounceKey]{
		Name: "id",
		FromObject: func(b *L2AnnounceEntry) index.KeySet {
			return index.NewKeySet(b.Key())
		},
		FromKey: func(id L2AnnounceKey) []byte {
			return id.Key()
		},
		Unique: true,
	}

	L2AnnounceOriginIndex = statedb2.Index[*L2AnnounceEntry, resource.Key]{
		Name: "origin",
		FromObject: func(b *L2AnnounceEntry) index.KeySet {
			return index.StringerSlice(b.Origins)
		},
		FromKey: func(id resource.Key) []byte {
			return index.Stringer(id)
		},
	}

	L2AnnounceTableCell = statedb2.NewTableCell[*L2AnnounceEntry](
		"l2-announce",
		L2AnnounceIDIndex,
		L2AnnounceOriginIndex,
	)
)
