// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stats

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/u8proto"
)

// snatTupleAccessor is an interface for safely accessing elements of the SNAT tuple.
// Instead of passing the tuple directly, we use the snatTupleAccessor interface
// which provide opaque access to SNAT specific data such as egress-ip and
// endpoint-ip.
//
// This provides dual benefits of abstracting away concerns regarding snat
// tuple direction, as well as ensuring data integrity by only providing a
// opaque accessor to external observers.
type SNATTupleAccessor interface {
	GetEgressAddr() (netip.Addr, uint16)
	GetEndpointAddr() (netip.Addr, uint16)
	GetProto() u8proto.U8proto
}

// have constraint under different type such that we can use this for both
// passing map[snatTupleConstraint]uint16 as well as using it as a regular
// accessor interface type.
type snatTupleConstraint interface {
	comparable
	SNATTupleAccessor
}

type SNATTuple4 tuple.TupleKey4
type SNATTuple6 tuple.TupleKey6

func (t SNATTuple4) getRelativeValues() (egressIP, endpointIP netip.Addr, egressPort, endpointPort uint16) {
	switch t.Flags {
	case tuple.TUPLE_F_IN:
		return t.DestAddr.Addr(), t.SourceAddr.Addr(), t.DestPort, t.SourcePort
	default:
		return t.SourceAddr.Addr(), t.DestAddr.Addr(), t.DestPort, t.SourcePort
	}
}

func (t SNATTuple6) getRelativeValues() (egressIP, endpointIP netip.Addr, egressPort, endpointPort uint16) {
	switch t.Flags {
	case tuple.TUPLE_F_IN:
		return t.DestAddr.Addr(), t.SourceAddr.Addr(), t.DestPort, t.SourcePort
	default:
		return t.SourceAddr.Addr(), t.DestAddr.Addr(), t.DestPort, t.SourcePort
	}
}

func (t SNATTuple4) GetProto() u8proto.U8proto {
	return t.NextHeader
}

func (t SNATTuple4) GetEgressAddr() (netip.Addr, uint16) {
	egressIP, _, egressPort, _ := t.getRelativeValues()
	return egressIP, egressPort
}

func (t SNATTuple4) GetEndpointAddr() (netip.Addr, uint16) {
	_, endpointIP, _, endpointPort := t.getRelativeValues()
	return endpointIP, endpointPort
}

func (t SNATTuple6) GetEgressAddr() (netip.Addr, uint16) {
	egressIP, _, egressPort, _ := t.getRelativeValues()
	return egressIP, egressPort
}

func (t SNATTuple6) GetEndpointAddr() (netip.Addr, uint16) {
	_, endpointIP, _, endpointPort := t.getRelativeValues()
	return endpointIP, endpointPort
}

func (t SNATTuple6) GetProto() u8proto.U8proto {
	return t.NextHeader
}

func toIter[T snatTupleConstraint](s map[T]uint16) TupleCountIterator {
	return func(yield func(SNATTupleAccessor, uint16) bool) {
		for k, v := range s {
			yield(k, v)
		}
	}
}
