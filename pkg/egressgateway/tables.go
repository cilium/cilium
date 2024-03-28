// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
)

var (
	PolicyConfigIDIndex = statedb.Index[PolicyConfig, string]{
		Name: "id",
		FromObject: func(p PolicyConfig) index.KeySet {
			return index.NewKeySet(index.Stringer(p.id))
		},
		FromKey: index.String,
		Unique:  true,
	}
)

func NewPolicyConfigTable() (statedb.RWTable[PolicyConfig], error) {
	return statedb.NewTable[PolicyConfig](
		"policy-configs",
		PolicyConfigIDIndex,
	)
}

var (
	EndpointMetadataIDIndex = statedb.Index[endpointMetadata, endpointID]{
		Name: "id",
		FromObject: func(em endpointMetadata) index.KeySet {
			return index.NewKeySet(index.String(string(em.id)))
		},
		FromKey: func(eid endpointID) index.Key {
			return index.String(string(eid))
		},
		Unique: true,
	}
)

func NewEndpointMetadataTable() (statedb.RWTable[endpointMetadata], error) {
	return statedb.NewTable[endpointMetadata](
		"endpoint-metadata",
		EndpointMetadataIDIndex,
	)
}
