// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

import (
	bpfTypes "github.com/cilium/cilium/pkg/bpf/types"
	"github.com/cilium/cilium/pkg/mac"
)

type Pad4uint32 [4]uint32

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Pad4uint32) DeepCopyInto(out *Pad4uint32) {
	copy(out[:], in[:])
}

type EndpointInfo struct {
	IfIndex uint32 `align:"ifindex"`
	Unused  uint16 `align:"unused"`
	LxcID   uint16 `align:"lxc_id"`
	Flags   uint32 `align:"flags"`
	// go alignment
	_       uint32
	MAC     mac.Uint64MAC `align:"mac"`
	NodeMAC mac.Uint64MAC `align:"node_mac"`
	Pad     Pad4uint32    `align:"pad"`
}

type EndpointKey struct {
	bpfTypes.EndpointKey
}
