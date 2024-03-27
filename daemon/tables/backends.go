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

	// TODO this is the name of the EndpointSlice. This is used to clean up
	// backends removed from an EndpointSlice. Need to rethink the naming for
	// the fields though. Perhaps just have one string field?
	// FIXME how to deal with backends that are owned by many?
	Owner  string
	Source source.Source

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

func (be *Backend) ToLoadBalancerBackend() *loadbalancer.Backend {
	return &loadbalancer.Backend{
		FEPortName: be.PortName,
		ID:         0,
		Weight:     be.Weight,
		NodeName:   be.NodeName,
		L3n4Addr:   be.L3n4Addr,
		State:      be.State,
		Preferred:  false, // TODO Preferred unused?
	}
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

	BackendOwnerIndex = statedb.Index[*Backend, string]{
		Name: "owner",
		FromObject: func(obj *Backend) index.KeySet {
			return index.NewKeySet(index.String(obj.Owner))
		},
		FromKey: index.String,
		Unique:  false,
	}
)

func NewBackendsTable(db *statedb.DB) (statedb.RWTable[*Backend], error) {
	tbl, err := statedb.NewTable(
		BackendsTableName,
		BackendAddrIndex,
		BackendServiceIndex,
		BackendOwnerIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}
