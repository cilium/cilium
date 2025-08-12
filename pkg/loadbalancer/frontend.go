// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"encoding/json"
	"fmt"
	"iter"
	"slices"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/util/duration"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// FrontendParams defines the static parameters of a frontend.
// This is separate from [Frontend] to clearly separate which fields
// can be manipulated and which are internally managed by [Writer].
type FrontendParams struct {
	// Frontend address and port
	Address L3n4Addr

	// Service type (e.g. ClusterIP, NodePort, ...)
	Type SVCType

	// Name of the associated service
	ServiceName ServiceName

	// PortName if set will select only backends with matching
	// port name.
	PortName FEPortName

	// ServicePort is the associated "ClusterIP" port of this frontend.
	// Same as [Address.L4Addr.Port] except when [Type] NodePort or
	//  This is used to match frontends with the [Ports] of
	// [Service.ProxyRedirect].
	ServicePort uint16
}

type Frontend struct {
	FrontendParams

	// Status is the reconciliation status for this frontend and
	// reflects whether or not the frontend and the associated backends
	// have been reconciled with the BPF maps.
	// Managed by [Writer].
	Status reconciler.Status

	// Backends associated with the frontend.
	Backends BackendsSeq2

	// HealthCheckBackends associated with the frontend that includes the ones that should be health checked.
	HealthCheckBackends BackendsSeq2

	// ID is the identifier allocated to this frontend. Used as the key
	// in the services BPF map. This field is populated by the reconciler
	// and is initially set to zero. It can be considered valid only when
	// [Status] is set to done.
	ID ServiceID

	// RedirectTo if set selects the backends from this service name instead
	// of that of [FrontendParams.ServiceName]. This is used to implement the
	// local redirect policies where traffic going to a specific service/frontend
	// is redirected to a local pod instead.
	RedirectTo *ServiceName

	// Service associated with the frontend. If service is updated
	// this pointer to the service will update as well and the
	// frontend is marked for reconciliation.
	Service *Service `json:"-" yaml:"-"`
}

// BackendsSeq2 is an iterator for sequence of backends that is also JSON and YAML
// marshalable.
type BackendsSeq2 iter.Seq2[BackendParams, statedb.Revision]

func (s BackendsSeq2) MarshalJSON() ([]byte, error) {
	return json.Marshal(slices.Collect(statedb.ToSeq(iter.Seq2[BackendParams, statedb.Revision](s))))
}

func (s BackendsSeq2) MarshalYAML() (any, error) {
	return slices.Collect(statedb.ToSeq(iter.Seq2[BackendParams, statedb.Revision](s))), nil
}

func (fe *Frontend) Clone() *Frontend {
	fe2 := *fe
	return &fe2
}

func (fe *Frontend) TableHeader() []string {
	return []string{
		"Address",
		"Type",
		"ServiceName",
		"PortName",
		"Backends",
		"RedirectTo",
		"Status",
		"Since",
		"Error",
	}
}

func (fe *Frontend) TableRow() []string {
	redirectTo := ""
	if fe.RedirectTo != nil {
		redirectTo = fe.RedirectTo.String()
	}
	return []string{
		fe.Address.StringWithProtocol(),
		string(fe.Type),
		fe.ServiceName.String(),
		string(fe.PortName),
		showBackends(fe.Backends),
		redirectTo,
		string(fe.Status.Kind),
		duration.HumanDuration(time.Since(fe.Status.UpdatedAt)),
		fe.Status.Error,
	}
}

func (fe *Frontend) ToModel() *models.Service {
	var natPolicy string

	svc := fe.Service

	id := int64(fe.ID)
	if svc.NatPolicy != SVCNatPolicyNone {
		natPolicy = string(svc.NatPolicy)
	}
	spec := &models.ServiceSpec{
		ID:              id,
		FrontendAddress: fe.Address.GetModel(),
		Flags: &models.ServiceSpecFlags{
			Type:                string(fe.Type),
			TrafficPolicy:       string(svc.ExtTrafficPolicy),
			ExtTrafficPolicy:    string(svc.ExtTrafficPolicy),
			IntTrafficPolicy:    string(svc.IntTrafficPolicy),
			NatPolicy:           natPolicy,
			HealthCheckNodePort: svc.HealthCheckNodePort,
			Name:                svc.Name.Name(),
			Namespace:           svc.Name.Namespace(),
		},
	}

	if fe.RedirectTo != nil {
		spec.Flags.Type = string(SVCTypeLocalRedirect)
	}

	if svc.Name.Cluster() != option.Config.ClusterName {
		spec.Flags.Cluster = svc.Name.Cluster()
	}

	backendModel := func(be BackendParams) *models.BackendAddress {
		addrClusterStr := be.Address.AddrCluster().String()
		state := be.State
		if be.Unhealthy {
			state = BackendStateQuarantined
		}
		stateStr, _ := state.String()
		return &models.BackendAddress{
			IP:        &addrClusterStr,
			Protocol:  be.Address.Protocol(),
			Port:      be.Address.Port(),
			NodeName:  be.NodeName,
			Zone:      be.Zone,
			State:     stateStr,
			Preferred: true,
			Weight:    &be.Weight,
		}
	}

	for be := range fe.Backends {
		spec.BackendAddresses = append(spec.BackendAddresses, backendModel(be))
	}

	return &models.Service{
		Spec: spec,
		Status: &models.ServiceStatus{
			Realized: spec,
		},
	}
}

// showBackends returns the backends associated with a frontend in form
// "1.2.3.4:80, [2001::1]:443"
func showBackends(bes BackendsSeq2) string {
	const maxToShow = 5
	count := 0
	var b strings.Builder
	for be := range bes {
		if count < maxToShow {
			b.WriteString(be.Address.String())
			b.WriteString(", ")
		}
		count++
	}
	s := b.String()
	s, _ = strings.CutSuffix(s, ", ")

	if count > maxToShow {
		s += fmt.Sprintf(" + %d more ...", count-maxToShow)
	}
	return s
}

var (
	frontendAddressIndex = statedb.Index[*Frontend, L3n4Addr]{
		Name: "address",
		FromObject: func(fe *Frontend) index.KeySet {
			return index.NewKeySet(fe.Address.Bytes())
		},
		FromKey: func(l L3n4Addr) index.Key {
			return index.Key(l.Bytes())
		},
		FromString: L3n4AddrFromString,
		Unique:     true,
	}

	FrontendByAddress = frontendAddressIndex.Query

	frontendServiceIndex = statedb.Index[*Frontend, ServiceName]{
		Name: "service",
		FromObject: func(fe *Frontend) index.KeySet {
			return index.NewKeySet(fe.ServiceName.Key())
		},
		FromKey:    ServiceName.Key,
		FromString: index.FromString,
		Unique:     false,
	}

	FrontendByServiceName = frontendServiceIndex.Query
)

const (
	FrontendTableName = "frontends"
)

func NewFrontendsTable(cfg Config, db *statedb.DB) (statedb.RWTable[*Frontend], error) {
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
