package tables

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
)

type BackendParams struct {
	loadbalancer.Backend

	Source        source.Source
	HintsForZones []string
}

type Backend struct {
	BackendParams

	ReferencedBy container.ImmSet[loadbalancer.ServiceName]
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
		be.L3n4Addr.String(),
		state,
		be.Source.String(),
		strings.Join(toStrings(be.ReferencedBy.AsSlice()), ", "),
	}
}

func (be *Backend) String() string {
	return fmt.Sprintf(
		"%s (source: %s, state: %v)",
		be.L3n4Addr.StringID(), be.Source, be.State,
	)

}

func (be *Backend) ToLoadBalancerBackend() *loadbalancer.Backend {
	return &be.Backend
}

func (be *Backend) removeRef(name loadbalancer.ServiceName) (*Backend, bool) {
	beCopy := *be
	beCopy.ReferencedBy = beCopy.ReferencedBy.Delete(name)
	return &beCopy, beCopy.ReferencedBy.Len() == 0
}

const (
	BackendTableName = "backends"
)

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
