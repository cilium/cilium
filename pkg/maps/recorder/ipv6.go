// Copyright 2021 Authors of Cilium
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

package recorder

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/types"
)

type CaptureWcard6 struct {
	DestAddr types.IPv6 `align:"daddr"`
	SrcAddr  types.IPv6 `align:"saddr"`
	DestPort uint16     `align:"dport"`
	SrcPort  uint16     `align:"sport"`
	NextHdr  uint8      `align:"nexthdr"`
	DestMask uint8      `align:"dmask"`
	SrcMask  uint8      `align:"smask"`
	Flags    uint8      `align:"flags"`
}

type CaptureRule6 CaptureRule

func (k *CaptureWcard6) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *CaptureWcard6) NewValue() bpf.MapValue    { return &CaptureRule6{} }
func (k *CaptureWcard6) DeepCopyMapKey() bpf.MapKey {
	return &CaptureWcard6{
		DestAddr: k.DestAddr,
		SrcAddr:  k.SrcAddr,
		DestPort: k.DestPort,
		SrcPort:  k.SrcPort,
		NextHdr:  k.NextHdr,
		DestMask: k.DestMask,
		SrcMask:  k.SrcMask,
		Flags:    k.Flags,
	}
}
func (k *CaptureWcard6) String() string {
	return fmt.Sprintf("%s/%d %s/%d %d %d %d\n",
		k.DestAddr,
		int(k.DestMask),
		k.SrcAddr,
		int(k.SrcMask),
		byteorder.NetworkToHost(k.DestPort),
		byteorder.NetworkToHost(k.SrcPort),
		int(k.NextHdr))
}

func (v *CaptureRule6) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *CaptureRule6) DeepCopyMapValue() bpf.MapValue {
	return &CaptureRule6{
		RuleId:   v.RuleId,
		Reserved: v.Reserved,
		CapLen:   v.CapLen,
	}
}
func (v *CaptureRule6) String() string {
	return fmt.Sprintf("%d %d", int(v.RuleId), int(v.CapLen))
}

var CaptureMap6 = bpf.NewMap(
	MapNameWcard6,
	bpf.MapTypeHash,
	&CaptureWcard6{}, int(unsafe.Sizeof(CaptureWcard6{})),
	&CaptureRule6{}, int(unsafe.Sizeof(CaptureRule6{})),
	MapSize,
	bpf.BPF_F_NO_PREALLOC, 0,
	bpf.ConvertKeyValue,
).WithCache()
