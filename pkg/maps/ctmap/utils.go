// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
