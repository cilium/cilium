package tables

import (
	"slices"

	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
)

type BackendParams struct {
	loadbalancer.L3n4Addr

	Source        source.Source
	NodeName      string
	PortName      string
	Weight        uint16
	State         loadbalancer.BackendState
	HintsForZones []string
}

type Backend struct {
	BackendParams

	ReferencedBy container.ImmSet[loadbalancer.ServiceName]
}

func (be *Backend) removeRef(name loadbalancer.ServiceName) (*Backend, bool) {
	beCopy := *be
	beCopy.ReferencedBy = beCopy.ReferencedBy.Delete(name)
	return &beCopy, beCopy.ReferencedBy.Len() == 0
}

const (
	BackendsTableName = "backends"
)

func l3n4AddrKey(addr loadbalancer.L3n4Addr) index.Key {
	return slices.Concat(
		index.NetIPAddr(addr.AddrCluster.Addr()),
		index.Uint16(addr.Port),
		index.String(addr.Protocol),
		index.Uint32(addr.AddrCluster.ClusterID()),
	)
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
		BackendsTableName,
		BackendAddrIndex,
		BackendServiceIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}
