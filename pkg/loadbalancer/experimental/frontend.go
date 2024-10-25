// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"net/netip"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/util/duration"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/time"
)

// FrontendParams defines the static parameters of a frontend.
// This is separate from [Frontend] to clearly separate which fields
// can be manipulated and which are internally managed by [Writer].
type FrontendParams struct {
	// Frontend address and port
	Address loadbalancer.L3n4Addr

	// Service type (e.g. ClusterIP, NodePort, ...)
	Type loadbalancer.SVCType

	// Name of the associated service
	ServiceName loadbalancer.ServiceName

	// PortName if set will select only backends with matching
	// port name.
	PortName loadbalancer.FEPortName
}

type Frontend struct {
	FrontendParams

	// Status is the reconciliation status for this frontend and
	// reflects whether or not the frontend and the associated backends
	// have been reconciled with the BPF maps.
	// Managed by [Writer].
	Status reconciler.Status

	// Backends associated with the frontend.
	Backends []BackendWithRevision

	// nodePortAddrs are the IP addresses on which to serve NodePort and HostPort
	// services. Not set if [Type] is not NodePort or HostPort. These are updated
	// when the Table[NodeAddress] changes.
	nodePortAddrs []netip.Addr

	// service associated with the frontend. If service is updated
	// this pointer to the service will update as well and the
	// frontend is marked for reconciliation.
	//
	// Private as it is managed by [Writer] and does not need to
	// be JSON serialized.
	service *Service
}

type BackendWithRevision struct {
	*Backend
	Revision statedb.Revision
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
		"ServiceName",
		"PortName",
		"Backends",
		"Status",
		"Since",
		"Error",
	}
}

func (fe *Frontend) TableRow() []string {
	return []string{
		fe.Address.StringWithProtocol(),
		string(fe.Type),
		fe.ServiceName.String(),
		string(fe.PortName),
		showBackends(fe.Backends),
		string(fe.Status.Kind),
		duration.HumanDuration(time.Since(fe.Status.UpdatedAt)),
		fe.Status.Error,
	}
}

// showBackends returns the backends associated with a frontend in form
// "1.2.3.4:80 (active), [2001::1]:443 (terminating)"
// TODO: Skip showing the state?
func showBackends(bes []BackendWithRevision) string {
	var b strings.Builder
	for i, be := range bes {
		b.WriteString(be.L3n4Addr.String())
		b.WriteString(" (")
		state, err := be.State.String()
		if err != nil {
			state = err.Error()
		}
		b.WriteString(state)
		b.WriteString(")")
		if i != len(bes)-1 {
			b.WriteString(", ")
		}
	}
	return b.String()
}

var (
	frontendAddressIndex = statedb.Index[*Frontend, loadbalancer.L3n4Addr]{
		Name: "frontends",
		FromObject: func(fe *Frontend) index.KeySet {
			return index.NewKeySet(fe.Address.Bytes())
		},
		FromKey: func(l loadbalancer.L3n4Addr) index.Key {
			return index.Key(l.Bytes())
		},
		Unique: true,
	}

	FrontendByAddress = frontendAddressIndex.Query

	frontendServiceIndex = statedb.Index[*Frontend, loadbalancer.ServiceName]{
		Name: "service",
		FromObject: func(fe *Frontend) index.KeySet {
			return index.NewKeySet(index.Stringer(fe.ServiceName))
		},
		FromKey: index.Stringer[loadbalancer.ServiceName],
		Unique:  false,
	}

	FrontendByServiceName = frontendServiceIndex.Query
)

const (
	FrontendTableName = "frontends"
)

func NewFrontendsTable(db *statedb.DB) (statedb.RWTable[*Frontend], error) {
	tbl, err := statedb.NewTable(
		FrontendTableName,
		frontendAddressIndex,
		frontendServiceIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}
