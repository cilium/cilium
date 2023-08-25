// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"strings"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/u8proto"
)

// IPFamily represents an IP family (i.e., either IPv4 or IPv6).
type IPFamily bool

const (
	// IPv4 represents the IPv4 IP family.
	IPv4 = IPFamily(true)
	// IPv6 represents the IPv6 IP family.
	IPv6 = IPFamily(false)
)

func (family IPFamily) String() string {
	if family == IPv4 {
		return "ipv4"
	}
	return "ipv6"
}

type NatKey interface {
	bpf.MapKey

	// ToNetwork converts fields to network byte order.
	ToNetwork() NatKey

	// ToHost converts fields to host byte order.
	ToHost() NatKey

	// Dump contents of key to sb. Returns true if successful.
	Dump(sb *strings.Builder, reverse bool) bool

	// GetFlags flags containing the direction of the TupleKey.
	GetFlags() uint8

	// GetNextHeader returns the proto of the NatKey
	GetNextHeader() u8proto.U8proto
}

// NatKey4 is needed to provide NatEntry type to Lookup values
type NatKey4 struct {
	tuple.TupleKey4Global
}

// SizeofNatKey4 is the size of the NatKey4 type in bytes.
const SizeofNatKey4 = int(unsafe.Sizeof(NatKey4{}))

// ToNetwork converts ports to network byte order.
//
// This is necessary to prevent callers from implicitly converting
// the NatKey4 type here into a local key type in the nested
// TupleKey4Global field.
func (k *NatKey4) ToNetwork() NatKey {
	return &NatKey4{
		TupleKey4Global: *k.TupleKey4Global.ToNetwork().(*tuple.TupleKey4Global),
	}
}

// ToHost converts ports to host byte order.
//
// This is necessary to prevent callers from implicitly converting
// the NatKey4 type here into a local key type in the nested
// TupleKey4Global field.
func (k *NatKey4) ToHost() NatKey {
	return &NatKey4{
		TupleKey4Global: *k.TupleKey4Global.ToHost().(*tuple.TupleKey4Global),
	}
}

func (k *NatKey4) GetNextHeader() u8proto.U8proto {
	return k.NextHeader
}

func (k *NatKey4) New() bpf.MapKey { return &NatKey4{} }

// NatKey6 is needed to provide NatEntry type to Lookup values
type NatKey6 struct {
	tuple.TupleKey6Global
}

// SizeofNatKey6 is the size of the NatKey6 type in bytes.
const SizeofNatKey6 = int(unsafe.Sizeof(NatKey6{}))

// ToNetwork converts ports to network byte order.
//
// This is necessary to prevent callers from implicitly converting
// the NatKey6 type here into a local key type in the nested
// TupleKey6Global field.
func (k *NatKey6) ToNetwork() NatKey {
	return &NatKey6{
		TupleKey6Global: *k.TupleKey6Global.ToNetwork().(*tuple.TupleKey6Global),
	}
}

// ToHost converts ports to host byte order.
//
// This is necessary to prevent callers from implicitly converting
// the NatKey6 type here into a local key type in the nested
// TupleKey6Global field.
func (k *NatKey6) ToHost() NatKey {
	return &NatKey6{
		TupleKey6Global: *k.TupleKey6Global.ToHost().(*tuple.TupleKey6Global),
	}
}

func (k *NatKey6) GetNextHeader() u8proto.U8proto {
	return k.NextHeader
}

func (k *NatKey6) New() bpf.MapKey { return &NatKey6{} }
