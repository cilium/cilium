package tables

import (
	"slices"

	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

type BackendParams struct {
	loadbalancer.L3n4Addr

	Source    source.Source
	PortName  string
	NodeName  string
	Weight    uint16
	State     loadbalancer.BackendState
	Preferred loadbalancer.Preferred
}

type Backend struct {
	BackendParams

	ID           loadbalancer.BackendID
	ReferencedBy container.ImmSet[loadbalancer.ServiceName]
	BPFStatus    reconciler.Status
}

func (be *Backend) removeRef(name loadbalancer.ServiceName) *Backend {
	beCopy := *be
	beCopy.ReferencedBy = beCopy.ReferencedBy.Delete(name)
	if beCopy.ReferencedBy.Len() == 0 {
		beCopy.BPFStatus = reconciler.StatusPendingDelete()
	}

	return &beCopy
}

const (
	BackendsTableName = "backends"
)

func l3n4AddrKey(addr loadbalancer.L3n4Addr) index.Key {
	// <clusterID> <IP addr> <port> <protocol> <scope>
	return slices.Concat(
		index.Uint32(addr.AddrCluster.ClusterID()),
		index.NetIPAddr(addr.AddrCluster.Addr()),
		index.Uint16(addr.Port),
		index.String(addr.Protocol),
		[]byte{addr.Scope},
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
