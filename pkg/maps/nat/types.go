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
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type NatKey4 struct {
	tuple.TupleKey4Global
}

// SizeofNatKey4 is the size of the NatKey4 type in bytes.
const SizeofNatKey4 = int(unsafe.Sizeof(NatKey4{}))

// NewValue creates a new bpf.MapValue.
func (k *NatKey4) NewValue() bpf.MapValue { return &NatEntry4{} }

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

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *NatKey4) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

func (k *NatKey4) GetNextHeader() u8proto.U8proto {
	return k.NextHeader
}

// NatKey6 is needed to provide NatEntry type to Lookup values
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type NatKey6 struct {
	tuple.TupleKey6Global
}

// SizeofNatKey6 is the size of the NatKey6 type in bytes.
const SizeofNatKey6 = int(unsafe.Sizeof(NatKey6{}))

// NewValue creates a new bpf.MapValue.
func (k *NatKey6) NewValue() bpf.MapValue { return &NatEntry6{} }

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

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *NatKey6) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

func (k *NatKey6) GetNextHeader() u8proto.U8proto {
	return k.NextHeader
}
