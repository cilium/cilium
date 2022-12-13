// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

import (
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

type Pad2uint8 [2]uint8

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Pad2uint8) DeepCopyInto(out *Pad2uint8) {
	copy(out[:], in[:])
	return
}

type RevNat4Key struct {
	Key uint16
}

type RevNat4Value struct {
	Address types.IPv4 `align:"address"`
	Port    uint16     `align:"port"`
}

type Service4Key struct {
	Address     types.IPv4 `align:"address"`
	Port        uint16     `align:"dport"`
	BackendSlot uint16     `align:"backend_slot"`
	Proto       uint8      `align:"proto"`
	Scope       uint8      `align:"scope"`
	Pad         Pad2uint8  `align:"pad"`
}

type Service4Value struct {
	BackendID uint32    `align:"$union0"`
	Count     uint16    `align:"count"`
	RevNat    uint16    `align:"rev_nat_index"`
	Flags     uint8     `align:"flags"`
	Flags2    uint8     `align:"flags2"`
	Pad       Pad2uint8 `align:"pad"`
}

type Backend4KeyV2 struct {
	ID loadbalancer.BackendID
}

type Backend4Key struct {
	ID uint16
}

type Backend4Value struct {
	Address types.IPv4      `align:"address"`
	Port    uint16          `align:"port"`
	Proto   u8proto.U8proto `align:"proto"`
	Flags   uint8           `align:"flags"`
}

type SockRevNat4Key struct {
	Cookie  uint64     `align:"cookie"`
	Address types.IPv4 `align:"address"`
	Port    int16      `align:"port"`
	Pad     int16      `align:"pad"`
}

type SockRevNat4Value struct {
	Address     types.IPv4 `align:"address"`
	Port        int16      `align:"port"`
	RevNatIndex uint16     `align:"rev_nat_index"`
}

type Backend4KeyV3 struct {
	ID loadbalancer.BackendID
}

type Backend4ValueV3 struct {
	Address   types.IPv4      `align:"address"`
	Port      uint16          `align:"port"`
	Proto     u8proto.U8proto `align:"proto"`
	Flags     uint8           `align:"flags"`
	ClusterID uint8           `align:"cluster_id"`
	Pad       pad3uint8       `align:"pad"`
}

type pad3uint8 [3]uint8
