// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rib

import (
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
)

var (
	// ID of the RIB. It consists of VRF + Prefix + Owner. This means even
	// if the VRF + Prefix can be duplicated when the Owner is different.
	RIBIDIndex = statedb.Index[Route, RouteID]{
		Name: "id",
		FromObject: func(rt Route) index.KeySet {
			rid := RouteID{
				VRF:    rt.VRF,
				Prefix: rt.Prefix,
				Owner:  rt.Owner,
			}
			return index.NewKeySet(rid.Key())
		},
		FromKey: RouteID.Key,
		Unique:  true,
	}

	// Index used by RIB processor to find the routes that have the same
	// VRF + Prefix. RIB processor performs best path selection against
	// these routes.
	RIBVRFPrefixIndex = statedb.Index[Route, VRFPrefix]{
		Name: "vrf-prefix",
		FromObject: func(rt Route) index.KeySet {
			vp := VRFPrefix{
				VRF:    rt.VRF,
				Prefix: rt.Prefix,
			}
			return index.NewKeySet(vp.Key())
		},
		FromKey: VRFPrefix.Key,
		Unique:  false,
	}

	// Index used by route owners to reconcile the desired routes against
	// the routes in the RIB.
	RIBOwnerIndex = statedb.Index[Route, Owner]{
		Name: "owner",
		FromObject: func(rt Route) index.KeySet {
			return index.NewKeySet(index.Uint16(uint16(rt.Owner.ID)))
		},
		FromKey: func(o Owner) index.Key { return index.Uint16(uint16(o.ID)) },
		Unique:  false,
	}

	// ID of the FIB. Unlike RIB, it doesn't contain owner because the FIB
	// only contains the "best" routes calculated from the RIB.
	FIBIDIndex = statedb.Index[Route, VRFPrefix]{
		Name: "id",
		FromObject: func(rt Route) index.KeySet {
			vp := VRFPrefix{
				VRF:    rt.VRF,
				Prefix: rt.Prefix,
			}
			return index.NewKeySet(vp.Key())
		},
		FromKey: VRFPrefix.Key,
		Unique:  true,
	}

	// Index used by dataplane to subscribe to the routes they are
	// interested in.
	FIBNextHopIndex = statedb.Index[Route, NextHopKind]{
		Name: "nexthop",
		FromObject: func(rt Route) index.KeySet {
			return index.NewKeySet(index.Uint16(uint16(rt.NextHop.Kind())))
		},
		FromKey: func(k NextHopKind) index.Key {
			return index.Uint16(uint16(k))
		},
		Unique: false,
	}
)

type RIB statedb.RWTable[Route]

func newRIBTable() (RIB, error) {
	return statedb.NewTable[Route](
		"rib",
		RIBIDIndex,
		RIBVRFPrefixIndex,
		RIBOwnerIndex,
	)
}

type FIB statedb.RWTable[Route]

func newFIBTable() (FIB, error) {
	return statedb.NewTable[Route](
		"fib",
		FIBIDIndex,
		FIBNextHopIndex,
	)
}
