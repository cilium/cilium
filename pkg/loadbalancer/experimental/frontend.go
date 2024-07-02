// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"slices"
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

type Frontend struct {
	Address     loadbalancer.L3n4Addr    // Frontend address
	Type        loadbalancer.SVCType     // Service type
	ServiceName loadbalancer.ServiceName // Associated service

	// PortName if set will select only backends with matching
	// port name.
	PortName loadbalancer.FEPortName

	// service associated with the frontend. If service is updated
	// this pointer to the service will update as well and the
	// frontend is marked for reconciliation.
	//
	// Private as it is managed by [Services] and does not need to
	// be JSON serialized.
	service *Service

	// ID is the allocated numerical id for the frontend used in BPF
	// maps to refer to this service.
	ID loadbalancer.ID

	// Status is the reconciliation status for this frontend and
	// reflects whether or not the frontend and the associated backends
	// have been reconciled with the BPF maps.
	Status reconciler.Status
}

func (fe *Frontend) Service() *Service {
	return fe.service
}

func (fe *Frontend) Clone() *Frontend {
	fe2 := *fe
	return &fe2
}

func (fe *Frontend) setStatus(status reconciler.Status) *Frontend {
	fe.Status = status
	return fe
}

func (fe *Frontend) getStatus() reconciler.Status {
	return fe.Status
}

func (fe *Frontend) TableHeader() []string {
	return []string{
		"Address",
		"Type",
		"PortName",
		"ServiceName",
		"ID",
		"Status",
	}
}

func (fe *Frontend) TableRow() []string {
	return []string{
		fe.Address.StringWithProtocol(),
		string(fe.Type),
		string(fe.PortName),
		fe.ServiceName.String(),
		strconv.FormatUint(uint64(fe.ID), 10),
		fe.Status.String(),
	}
}

// l3n4AddrKey computes the StateDB key to use for L3n4Addr.
func l3n4AddrKey(addr loadbalancer.L3n4Addr) index.Key {
	return slices.Concat(
		index.NetIPAddr(addr.AddrCluster.Addr()),
		index.Uint16(addr.Port),
		index.String(addr.Protocol),
		index.Uint32(addr.AddrCluster.ClusterID()),
		[]byte{addr.Scope},
	)
}

var (
	FrontendAddressIndex = statedb.Index[*Frontend, loadbalancer.L3n4Addr]{
		Name: "frontends",
		FromObject: func(fe *Frontend) index.KeySet {
			return index.NewKeySet(l3n4AddrKey(fe.Address))
		},
		FromKey: l3n4AddrKey,
		Unique:  true,
	}

	FrontendServiceIndex = statedb.Index[*Frontend, loadbalancer.ServiceName]{
		Name: "service",
		FromObject: func(fe *Frontend) index.KeySet {
			return index.NewKeySet(index.Stringer(fe.ServiceName))
		},
		FromKey: index.Stringer[loadbalancer.ServiceName],
		Unique:  false,
	}
)

const (
	FrontendTableName = "frontends"
)

func NewFrontendsTable(db *statedb.DB) (statedb.RWTable[*Frontend], error) {
	tbl, err := statedb.NewTable(
		FrontendTableName,
		FrontendAddressIndex,
		FrontendServiceIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

func GetBackendsForFrontend(txn statedb.ReadTxn, tbl statedb.Table[*Backend], fe *Frontend) statedb.Iterator[*Backend] {
	// TODO: Here we would filter out backends based on their state and on frontend properties such as the PortName.
	return tbl.List(txn, BackendServiceIndex.Query(fe.ServiceName))
}
