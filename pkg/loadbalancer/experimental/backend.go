// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"fmt"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
)

const (
	BackendTableName = "backends"
)

// Backend describes a backend for one or more services.
//
// This embeds the loadbalancer.Backend and adds further fields to it. Eventually
// we'd unify them, but for now we do not want to affect existing code yet.
type Backend struct {
	loadbalancer.Backend

	// Cluster in which the backend resides
	Cluster string

	// Source of the backend
	Source source.Source

	// ReferencedBy is the set of services referencing this backend.
	// This is managed by [Services].
	ReferencedBy container.ImmSet[loadbalancer.ServiceName]
}

func (be *Backend) String() string {
	return strings.Join(be.TableRow(), " ")
}

func (be *Backend) TableHeader() []string {
	return []string{
		"Address",
		"State",
		"Source",
		"ReferencedBy",
	}
}

func toStrings[T fmt.Stringer](xs []T) []string {
	out := make([]string, len(xs))
	for i := range xs {
		out[i] = xs[i].String()
	}
	return out
}

func (be *Backend) TableRow() []string {
	state, err := be.State.String()
	if err != nil {
		state = err.Error()
	}
	return []string{
		be.L3n4Addr.StringWithProtocol(),
		state,
		string(be.Source),
		strings.Join(toStrings(be.ReferencedBy.AsSlice()), ", "),
	}
}

func (be *Backend) release(name loadbalancer.ServiceName) (*Backend, bool) {
	beCopy := *be
	beCopy.ReferencedBy = beCopy.ReferencedBy.Delete(name)
	return &beCopy, beCopy.ReferencedBy.Len() == 0
}

// Clone returns a shallow clone of the backend.
func (be *Backend) Clone() *Backend {
	be2 := *be
	return &be2
}

var (
	BackendAddrIndex = statedb.Index[*Backend, loadbalancer.L3n4Addr]{
		Name: "addr",
		FromObject: func(obj *Backend) index.KeySet {
			return index.NewKeySet(l3n4AddrKey(obj.L3n4Addr))
		},
		FromKey: l3n4AddrKey,
		Unique:  true,
	}

	BackendServiceIndex = statedb.Index[*Backend, loadbalancer.ServiceName]{
		Name: "service-name",
		FromObject: func(obj *Backend) index.KeySet {
			return index.StringerSlice(obj.ReferencedBy.AsSlice())
		},
		FromKey: index.Stringer[loadbalancer.ServiceName],
		Unique:  false,
	}
)

func NewBackendsTable(db *statedb.DB) (statedb.RWTable[*Backend], error) {
	tbl, err := statedb.NewTable(
		BackendTableName,
		BackendAddrIndex,
		BackendServiceIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}
