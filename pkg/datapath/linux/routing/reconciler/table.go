// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"net/netip"
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	statedbReconciler "github.com/cilium/statedb/reconciler"
)

const endpointRulesTableName = "endpoint-routing-rules"

// EndpointRules is the desired policy-routing state for one local endpoint address.
type EndpointRules struct {
	Address netip.Addr

	// Owner identifies the endpoint that published the desired state.
	Owner string
	// Generation distinguishes successive endpoints that use the same owner and
	// address.
	Generation uint64

	Status statedbReconciler.Status
}

func (er *EndpointRules) Clone() *EndpointRules {
	er2 := *er
	return &er2
}

func (er *EndpointRules) SetStatus(status statedbReconciler.Status) *EndpointRules {
	er.Status = status
	return er
}

func (er *EndpointRules) GetStatus() statedbReconciler.Status {
	return er.Status
}

func (er *EndpointRules) TableHeader() []string {
	return []string{"Address", "Owner", "Generation", "Status"}
}

func (er *EndpointRules) TableRow() []string {
	return []string{
		er.Address.String(),
		er.Owner,
		strconv.FormatUint(er.Generation, 10),
		er.Status.String(),
	}
}

var endpointRulesAddressIndex = statedb.Index[*EndpointRules, netip.Addr]{
	Name: "address",
	FromObject: func(obj *EndpointRules) index.KeySet {
		return index.NewKeySet(index.NetIPAddr(obj.Address))
	},
	FromKey:    index.NetIPAddr,
	FromString: index.NetIPAddrString,
	Unique:     true,
}

func newEndpointRulesTable(db *statedb.DB) (statedb.RWTable[*EndpointRules], error) {
	return statedb.NewTable(
		db,
		endpointRulesTableName,
		endpointRulesAddressIndex,
	)
}
