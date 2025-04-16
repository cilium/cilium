// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"fmt"
	"sort"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/option"
)

// Preferred indicates if this backend is preferred to be load balanced.
type Preferred bool

// LegacyBackend represents load balancer backend.
//
// Deprecated: Superceded by [Backend] from the new load-balancer implementation.
// +k8s:deepcopy-gen=true
type LegacyBackend struct {
	// FEPortName is the frontend port name. This is used to filter backends sending to EDS.
	FEPortName string
	// ID of the backend
	ID BackendID
	// Weight of backend
	Weight uint16
	// Node hosting this backend. This is used to determine backends local to
	// a node.
	NodeName string
	// Zone where backend is located.
	ZoneID uint8
	L3n4Addr
	// State of the backend for load-balancing service traffic
	State BackendState
	// Preferred indicates if the healthy backend is preferred
	Preferred Preferred
}

func (b *LegacyBackend) String() string {
	state, _ := b.State.String()
	return "[" + b.L3n4Addr.String() + "," + "State:" + state + "]"
}

func (b *LegacyBackend) GetBackendModel() *models.BackendAddress {
	if b == nil {
		return nil
	}

	addrClusterStr := b.AddrCluster.String()
	stateStr, _ := b.State.String()
	return &models.BackendAddress{
		IP:        &addrClusterStr,
		Protocol:  b.Protocol,
		Port:      b.Port,
		NodeName:  b.NodeName,
		Zone:      option.Config.GetZone(b.ZoneID),
		State:     stateStr,
		Preferred: bool(b.Preferred),
		Weight:    &b.Weight,
	}
}

// NewLegacyBackend creates the Backend struct instance from given params.
// The default state for the returned Backend is BackendStateActive.
//
// Deprecated: Superceded by new load-balancer implementation.
func NewLegacyBackend(id BackendID, protocol L4Type, addrCluster cmtypes.AddrCluster, portNumber uint16) *LegacyBackend {
	return NewBackendWithState(id, protocol, addrCluster, portNumber, 0, BackendStateActive)
}

// NewBackendWithState creates the Backend struct instance from given params.
//
// Deprecated: Superceded by new load-balancer implementation.
func NewBackendWithState(id BackendID, protocol L4Type, addrCluster cmtypes.AddrCluster, portNumber uint16, zone uint8,
	state BackendState) *LegacyBackend {
	lbport := NewL4Addr(protocol, portNumber)
	b := LegacyBackend{
		ID:       id,
		L3n4Addr: L3n4Addr{AddrCluster: addrCluster, L4Addr: *lbport},
		State:    state,
		Weight:   DefaultBackendWeight,
		ZoneID:   zone,
	}

	return &b
}

// Deprecated: Superceded by new load-balancer implementation.
func NewLegacyBackendFromBackendModel(base *models.BackendAddress) (*LegacyBackend, error) {
	if base.IP == nil {
		return nil, fmt.Errorf("missing IP address")
	}

	l4addr := NewL4Addr(base.Protocol, base.Port)
	addrCluster, err := cmtypes.ParseAddrCluster(*base.IP)
	if err != nil {
		return nil, err
	}
	state, err := GetBackendState(base.State)
	if err != nil {
		return nil, fmt.Errorf("invalid backend state [%s]", base.State)
	}

	b := &LegacyBackend{
		NodeName:  base.NodeName,
		ZoneID:    option.Config.GetZoneID(base.Zone),
		L3n4Addr:  L3n4Addr{AddrCluster: addrCluster, L4Addr: *l4addr},
		State:     state,
		Preferred: Preferred(base.Preferred),
	}

	if base.Weight != nil {
		b.Weight = *base.Weight
	}

	if b.Weight == 0 {
		b.State = BackendStateMaintenance
	}

	return b, nil
}

func NewL3n4AddrFromBackendModel(base *models.BackendAddress) (*L3n4Addr, error) {
	if base.IP == nil {
		return nil, fmt.Errorf("missing IP address")
	}

	l4addr := NewL4Addr(base.Protocol, base.Port)
	addrCluster, err := cmtypes.ParseAddrCluster(*base.IP)
	if err != nil {
		return nil, err
	}
	return &L3n4Addr{AddrCluster: addrCluster, L4Addr: *l4addr}, nil
}

// LegacySVC is a structure for storing service details.
//
// Deprecated: Superceded by the new load-balancer implementation. New type
// with similar purpose is [Frontend].
// +k8s:deepcopy-gen=true
type LegacySVC struct {
	Frontend                  L3n4AddrID        // SVC frontend addr and an allocated ID
	Backends                  []*LegacyBackend  // List of service backends
	Type                      SVCType           // Service type
	ForwardingMode            SVCForwardingMode // Service mode (DSR vs SNAT)
	ExtTrafficPolicy          SVCTrafficPolicy  // Service external traffic policy
	IntTrafficPolicy          SVCTrafficPolicy  // Service internal traffic policy
	NatPolicy                 SVCNatPolicy      // Service NAT 46/64 policy
	SourceRangesPolicy        SVCSourceRangesPolicy
	ProxyDelegation           SVCProxyDelegation
	SessionAffinity           bool
	SessionAffinityTimeoutSec uint32
	HealthCheckNodePort       uint16                    // Service health check node port
	Name                      ServiceName               // Fully qualified service name
	LoadBalancerAlgorithm     SVCLoadBalancingAlgorithm // Service LB algorithm (random or maglev)
	LoadBalancerSourceRanges  []*cidr.CIDR
	L7LBProxyPort             uint16 // Non-zero for L7 LB services
	LoopbackHostport          bool
	Annotations               map[string]string
}

func (s *LegacySVC) GetModel() *models.Service {
	var natPolicy string
	type backendPlacement struct {
		pos int
		id  BackendID
	}

	if s == nil {
		return nil
	}

	id := int64(s.Frontend.ID)
	if s.NatPolicy != SVCNatPolicyNone {
		natPolicy = string(s.NatPolicy)
	}
	spec := &models.ServiceSpec{
		ID:               id,
		FrontendAddress:  s.Frontend.GetModel(),
		BackendAddresses: make([]*models.BackendAddress, len(s.Backends)),
		Flags: &models.ServiceSpecFlags{
			Type:                string(s.Type),
			TrafficPolicy:       string(s.ExtTrafficPolicy),
			ExtTrafficPolicy:    string(s.ExtTrafficPolicy),
			IntTrafficPolicy:    string(s.IntTrafficPolicy),
			NatPolicy:           natPolicy,
			HealthCheckNodePort: s.HealthCheckNodePort,

			Name:      s.Name.Name,
			Namespace: s.Name.Namespace,
		},
	}

	if s.Name.Cluster != option.Config.ClusterName {
		spec.Flags.Cluster = s.Name.Cluster
	}

	placements := make([]backendPlacement, len(s.Backends))
	for i, be := range s.Backends {
		placements[i] = backendPlacement{pos: i, id: be.ID}
	}
	sort.Slice(placements,
		func(i, j int) bool { return placements[i].id < placements[j].id })
	for i, placement := range placements {
		spec.BackendAddresses[i] = s.Backends[placement.pos].GetBackendModel()
	}

	return &models.Service{
		Spec: spec,
		Status: &models.ServiceStatus{
			Realized: spec,
		},
	}
}
