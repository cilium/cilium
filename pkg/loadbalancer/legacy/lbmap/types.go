// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
)

type (
	RevNatKey   = maps.RevNatKey
	RevNatValue = maps.RevNatValue

	ServiceKey   = maps.ServiceKey
	ServiceValue = maps.ServiceValue

	Backend      = maps.Backend
	BackendKey   = maps.BackendKey
	BackendValue = maps.BackendValue
)

func svcFrontend(svcKey ServiceKey, svcValue ServiceValue) *loadbalancer.L3n4AddrID {
	feIP := svcKey.GetAddress()
	feAddrCluster := cmtypes.MustAddrClusterFromIP(feIP)
	p := loadbalancer.NewL4TypeFromNumber(svcKey.GetProtocol())
	feL3n4Addr := loadbalancer.NewL3n4Addr(p, feAddrCluster, svcKey.GetPort(), svcKey.GetScope())
	feL3n4AddrID := &loadbalancer.L3n4AddrID{
		L3n4Addr: *feL3n4Addr,
		ID:       loadbalancer.ID(svcValue.GetRevNat()),
	}
	return feL3n4AddrID
}

func svcBackend(backendID loadbalancer.BackendID, backend BackendValue, backendFlags loadbalancer.ServiceFlags) *loadbalancer.LegacyBackend {
	beIP := backend.GetAddress()
	beAddrCluster := cmtypes.MustAddrClusterFromIP(beIP)
	bePort := backend.GetPort()
	beProto := loadbalancer.NewL4TypeFromNumber(backend.GetProtocol())
	beState := loadbalancer.GetBackendStateFromFlags(backend.GetFlags())
	beZone := backend.GetZone()
	if beState == loadbalancer.BackendStateActive && backendFlags.SVCSlotQuarantined() {
		beState = loadbalancer.BackendStateQuarantined
	}
	beBackend := loadbalancer.NewBackendWithState(backendID, beProto, beAddrCluster, bePort, beZone, beState)
	return beBackend
}
