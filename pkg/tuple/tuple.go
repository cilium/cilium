// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tuple

import (
	"strings"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	TUPLE_F_OUT     = 0
	TUPLE_F_IN      = 1
	TUPLE_F_RELATED = 2
	TUPLE_F_SERVICE = 4
)

// TupleKey is the interface describing keys to the conntrack and NAT maps.
type TupleKey interface {
	bpf.MapKey

	// ToNetwork converts fields to network byte order.
	ToNetwork() TupleKey

	// ToHost converts fields to host byte order.
	ToHost() TupleKey

	// Dumps contents of key to sb. Returns true if successful.
	Dump(sb *strings.Builder, reverse bool) bool

	// Returns flags containing the direction of the tuple key.
	GetFlags() uint8
}

type buff256uint8 [256]uint8

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *buff256uint8) DeepCopyInto(out *buff256uint8) {
	copy(out[:], in[:])
	return
}

// TupleValStub is a dummy, unused.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type TupleValStub struct {
	buff buff256uint8
}

// GetValuePtr returns the unsafe.Pointer for s.
func (t *TupleValStub) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(t) }

// String stub method.
func (t *TupleValStub) String() string {
	return "<TupleValStub>"
}
