// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package ctmap

import (
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/tuple"
)

// NOTE: the function does NOT copy addr fields, so it's not safe to
// reuse the returned natKey.
func oNatKeyFromReverse(k nat.NatKey, v nat.NatEntry) nat.NatKey {
	natKey, ok := k.(*nat.NatKey4)
	if ok { // ipv4
		natVal := v.(*nat.NatEntry4)
		return &nat.NatKey4{TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: natVal.Addr,
				SourcePort: natVal.Port,
				DestAddr:   natKey.SourceAddr,
				DestPort:   natKey.SourcePort,
				NextHeader: natKey.NextHeader,
				Flags:      tuple.TUPLE_F_OUT,
			}}}
	}

	{ // ipv6
		natKey := k.(*nat.NatKey6)
		natVal := v.(*nat.NatEntry6)
		return &nat.NatKey6{TupleKey6Global: tuple.TupleKey6Global{
			TupleKey6: tuple.TupleKey6{
				SourceAddr: natVal.Addr,
				SourcePort: natVal.Port,
				DestAddr:   natKey.SourceAddr,
				DestPort:   natKey.SourcePort,
				NextHeader: natKey.NextHeader,
				Flags:      tuple.TUPLE_F_OUT,
			}}}
	}
}

// NOTE: the function does NOT copy addr fields, so it's not safe to
// reuse the returned ctKey.
func egressCTKeyFromIngressNatKeyAndVal(k nat.NatKey, v nat.NatEntry) bpf.MapKey {
	natKey, ok := k.(*nat.NatKey4)
	if ok { // ipv4
		natVal := v.(*nat.NatEntry4)
		return &tuple.TupleKey4Global{TupleKey4: tuple.TupleKey4{
			// Workaround #5848
			SourceAddr: natKey.SourceAddr,
			DestPort:   natKey.SourcePort,
			DestAddr:   natVal.Addr,
			SourcePort: natVal.Port,
			NextHeader: natKey.NextHeader,
			Flags:      tuple.TUPLE_F_OUT,
		}}
	}

	{ // ipv6
		natKey := k.(*nat.NatKey6)
		natVal := v.(*nat.NatEntry6)
		return &tuple.TupleKey6Global{TupleKey6: tuple.TupleKey6{
			// Workaround #5848
			SourceAddr: natKey.SourceAddr,
			DestPort:   natKey.SourcePort,
			DestAddr:   natVal.Addr,
			SourcePort: natVal.Port,
			NextHeader: natKey.NextHeader,
			Flags:      tuple.TUPLE_F_OUT,
		}}
	}
}
