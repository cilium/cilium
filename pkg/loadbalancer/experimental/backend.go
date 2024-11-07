// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/part"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
)

const (
	BackendTableName = "backends"
)

// BackendParams defines the parameters of a backend for insertion into the backends table.
type BackendParams struct {
	loadbalancer.L3n4Addr

	// PortName is the frontend port name. If a frontend has specified a port name
	// only the backends with matching port name are selected.
	PortName string

	// Weight of backend for load-balancing.
	Weight uint16

	// Node hosting this backend. This is used to determine backends local to
	// a node.
	NodeName string

	// Zone where backend is located.
	ZoneID uint8

	// State of the backend for load-balancing service traffic
	State loadbalancer.BackendState
}

// Backend is a composite of the per-service backend instances that share the same
// IP address and port.
type Backend struct {
	loadbalancer.L3n4Addr

	// State is the learned state of the backend that combines the state of the
	// instances and the results of health checking.
	State loadbalancer.BackendState

	// Node hosting this backend. This is used to determine backends local to
	// a node.
	NodeName string

	// Zone where backend is located.
	ZoneID uint8

	// Instances of this backend. A backend is always linked to a specific
	// service and the instances may call the backend by different name
	// (PortName) or they may come from  differents sources.
	Instances part.Map[loadbalancer.ServiceName, BackendInstance]

	// Properties are additional untyped properties that can carry feature
	// specific metadata about the backend.
	Properties part.Map[string, any]
}

// BackendInstance defines the backend's properties associated with a specific
// service.
type BackendInstance struct {
	// PortName is the frontend port name used for filtering the backends
	// associated with a service.
	PortName string

	// Weight is the load-balancing weight for this backend in association
	// with a specific service.
	Weight uint16

	// Source is the data source from which this backend came from.
	Source source.Source

	// State is the backend's state as defined by the data source. This is
	// taken as input along with learned state (e.g. via health checking) to
	// construct the definite state.
	State loadbalancer.BackendState
}

func (be *Backend) String() string {
	return strings.Join(be.TableRow(), " ")
}

func (be *Backend) TableHeader() []string {
	return []string{
		"Address",
		"State",
		"Instances",
		"NodeName",
		"ZoneID",
	}
}

func (be *Backend) TableRow() []string {
	state, err := be.State.String()
	if err != nil {
		state = err.Error()
	}
	return []string{
		be.StringWithProtocol(),
		state,
		showInstances(be.Instances),
		be.NodeName,
		strconv.FormatUint(uint64(be.ZoneID), 10),
	}
}

func showInstances(instances part.Map[loadbalancer.ServiceName, BackendInstance]) string {
	var b strings.Builder
	count := instances.Len()
	for name, inst := range instances.All() {
		b.WriteString(name.String())
		if inst.PortName != "" {
			b.WriteString(" (")
			b.WriteString(string(inst.PortName))
			b.WriteRune(')')
		}
		count--
		if count > 0 {
			b.WriteString(", ")
		}
	}
	return b.String()
}

func (be *Backend) serviceNameKeys() index.KeySet {
	if be.Instances.Len() == 1 {
		// Avoid allocating the slice.
		for name := range be.Instances.All() {
			return index.NewKeySet(index.String(name.String()))
		}
	}
	keys := make([]index.Key, 0, be.Instances.Len())
	for name := range be.Instances.All() {
		keys = append(keys, index.String(name.String()))
	}
	return index.NewKeySet(keys...)
}

func (be *Backend) release(name loadbalancer.ServiceName) (*Backend, bool) {
	beCopy := *be
	beCopy.Instances = beCopy.Instances.Delete(name)
	return &beCopy, beCopy.Instances.Len() == 0
}

// Clone returns a shallow clone of the backend.
func (be *Backend) Clone() *Backend {
	be2 := *be
	return &be2
}

var (
	backendAddrIndex = statedb.Index[*Backend, loadbalancer.L3n4Addr]{
		Name: "addr",
		FromObject: func(obj *Backend) index.KeySet {
			return index.NewKeySet(obj.L3n4Addr.Bytes())
		},
		FromKey: func(l loadbalancer.L3n4Addr) index.Key { return index.Key(l.Bytes()) },
		Unique:  true,
	}

	BackendByAddress = backendAddrIndex.Query

	backendServiceIndex = statedb.Index[*Backend, loadbalancer.ServiceName]{
		Name:       "service-name",
		FromObject: (*Backend).serviceNameKeys,
		FromKey:    index.Stringer[loadbalancer.ServiceName],
		Unique:     false,
	}

	BackendByServiceName = backendServiceIndex.Query
)

func NewBackendsTable(db *statedb.DB) (statedb.RWTable[*Backend], error) {
	tbl, err := statedb.NewTable(
		BackendTableName,
		backendAddrIndex,
		backendServiceIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}
