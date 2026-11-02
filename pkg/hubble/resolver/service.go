// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package resolver

import (
	"net/netip"

	"github.com/cilium/statedb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hubble/resolver/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/u8proto"
)

// ServiceGetter implements types.ServiceGetter using Cilium's load-balancing
// state.
type ServiceGetter struct {
	db        *statedb.DB
	frontends statedb.Table[*loadbalancer.Frontend]
}

func NewServiceGetter(db *statedb.DB, frontends statedb.Table[*loadbalancer.Frontend]) types.ServiceGetter {
	return &ServiceGetter{db: db, frontends: frontends}
}

// GetServiceByAddr implements types.ServiceGetter. It looks up the service
// by IP, port and protocol.
func (g *ServiceGetter) GetServiceByAddr(ip netip.Addr, port uint16, proto u8proto.U8proto) *flowpb.Service {
	var l4 loadbalancer.L4Type
	switch proto {
	case u8proto.TCP:
		l4 = loadbalancer.TCP
	case u8proto.UDP:
		l4 = loadbalancer.UDP
	case u8proto.SCTP:
		l4 = loadbalancer.SCTP
	default:
		return nil
	}
	if !ip.IsValid() {
		return nil
	}
	fe, found := loadbalancer.LookupFrontendByTuple(g.db.ReadTxn(), g.frontends, cmtypes.AddrClusterFrom(ip, 0), l4, port, loadbalancer.ScopeExternal)
	if !found {
		return nil
	}
	return &flowpb.Service{
		Namespace: fe.ServiceName.Namespace(),
		Name:      fe.ServiceName.Name(),
	}
}
