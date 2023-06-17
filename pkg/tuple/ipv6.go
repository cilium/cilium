// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tuple

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

// TupleKey6 represents the key for IPv6 entries in the local BPF conntrack map.
// Address field names are correct for return traffic, i.e., they are reversed
// compared to the original direction traffic.
type TupleKey6 struct {
	DestAddr   types.IPv6      `align:"daddr"`
	SourceAddr types.IPv6      `align:"saddr"`
	DestPort   uint16          `align:"dport"`
	SourcePort uint16          `align:"sport"`
	NextHeader u8proto.U8proto `align:"nexthdr"`
	Flags      uint8           `align:"flags"`
}

// ToNetwork converts TupleKey6 ports to network byte order.
func (k *TupleKey6) ToNetwork() TupleKey {
	n := *k
	n.SourcePort = byteorder.HostToNetwork16(n.SourcePort)
	n.DestPort = byteorder.HostToNetwork16(n.DestPort)
	return &n
}

// ToHost converts TupleKey6 ports to network byte order.
func (k *TupleKey6) ToHost() TupleKey {
	n := *k
	n.SourcePort = byteorder.NetworkToHost16(n.SourcePort)
	n.DestPort = byteorder.NetworkToHost16(n.DestPort)
	return &n
}

// GetFlags returns the tuple's flags.
func (k *TupleKey6) GetFlags() uint8 {
	return k.Flags
}

// String returns the tuple's string representation, doh.
func (k *TupleKey6) String() string {
	return fmt.Sprintf("[%s]:%d, %d, %d, %d", k.DestAddr, k.SourcePort, k.DestPort, k.NextHeader, k.Flags)
}

func (k *TupleKey6) New() bpf.MapKey { return &TupleKey6{} }

// Dump writes the contents of key to sb and returns true if the value for next
// header in the key is nonzero.
func (k TupleKey6) Dump(sb *strings.Builder, reverse bool) bool {
	var addrDest string

	if k.NextHeader == 0 {
		return false
	}

	// Addresses swapped, see issue #5848
	if reverse {
		addrDest = k.SourceAddr.String()
	} else {
		addrDest = k.DestAddr.String()
	}

	if k.Flags&TUPLE_F_IN != 0 {
		sb.WriteString(fmt.Sprintf("%s IN %s %d:%d ",
			k.NextHeader.String(), addrDest, k.SourcePort,
			k.DestPort),
		)
	} else {
		sb.WriteString(fmt.Sprintf("%s OUT %s %d:%d ",
			k.NextHeader.String(), addrDest, k.DestPort,
			k.SourcePort),
		)
	}

	if k.Flags&TUPLE_F_RELATED != 0 {
		sb.WriteString("related ")
	}

	if k.Flags&TUPLE_F_SERVICE != 0 {
		sb.WriteString("service ")
	}

	return true
}

// SwapAddresses swaps the tuple source and destination addresses.
func (t *TupleKey6) SwapAddresses() {
	tmp := t.SourceAddr
	t.SourceAddr = t.DestAddr
	t.DestAddr = tmp
}

// TupleKey6Global represents the key for IPv6 entries in the global BPF conntrack map.
type TupleKey6Global struct {
	TupleKey6
}

// GetFlags returns the tuple's flags.
func (k *TupleKey6Global) GetFlags() uint8 {
	return k.Flags
}

// String returns the tuple's string representation, doh.
func (k *TupleKey6Global) String() string {
	return fmt.Sprintf("[%s]:%d --> [%s]:%d, %d, %d", k.SourceAddr, k.SourcePort, k.DestAddr, k.DestPort, k.NextHeader, k.Flags)
}

// ToNetwork converts ports to network byte order.
//
// This is necessary to prevent callers from implicitly converting
// the TupleKey6Global type here into a local key type in the nested
// TupleKey6 field.
func (k *TupleKey6Global) ToNetwork() TupleKey {
	return &TupleKey6Global{
		TupleKey6: *k.TupleKey6.ToNetwork().(*TupleKey6),
	}
}

// ToHost converts ports to host byte order.
//
// This is necessary to prevent callers from implicitly converting
// the TupleKey6Global type here into a local key type in the nested
// TupleKey6 field.
func (k *TupleKey6Global) ToHost() TupleKey {
	return &TupleKey6Global{
		TupleKey6: *k.TupleKey6.ToHost().(*TupleKey6),
	}
}

// Dump writes the contents of key to sb and returns true if the value for next
// header in the key is nonzero.
func (k TupleKey6Global) Dump(sb *strings.Builder, reverse bool) bool {
	var addrSource, addrDest string

	if k.NextHeader == 0 {
		return false
	}

	// Addresses swapped, see issue #5848
	if reverse {
		addrSource = k.DestAddr.String()
		addrDest = k.SourceAddr.String()
	} else {
		addrSource = k.SourceAddr.String()
		addrDest = k.DestAddr.String()
	}

	if k.Flags&TUPLE_F_IN != 0 {
		sb.WriteString(fmt.Sprintf("%s IN [%s]:%d -> [%s]:%d ",
			k.NextHeader.String(), addrSource, k.SourcePort,
			addrDest, k.DestPort),
		)
	} else {
		sb.WriteString(fmt.Sprintf("%s OUT [%s]:%d -> [%s]:%d ",
			k.NextHeader.String(), addrSource, k.SourcePort,
			addrDest, k.DestPort),
		)
	}

	if k.Flags&TUPLE_F_RELATED != 0 {
		sb.WriteString("related ")
	}

	if k.Flags&TUPLE_F_SERVICE != 0 {
		sb.WriteString("service ")
	}

	return true
}
