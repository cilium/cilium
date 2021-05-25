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
	"strings"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

type CaptureWcard4 struct {
	SrcAddr  types.IPv4 `align:"saddr"`
	DestAddr types.IPv4 `align:"daddr"`
	SrcPort  uint16     `align:"sport"`
	DestPort uint16     `align:"dport"`
	NextHdr  uint8      `align:"nexthdr"`
	SrcMask  uint8      `align:"smask"`
	DestMask uint8      `align:"dmask"`
	Flags    uint8      `align:"flags"`
}

type CaptureRule4 CaptureRule

func (k *CaptureWcard4) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

func (k *CaptureWcard4) NewValue() bpf.MapValue { return &CaptureRule4{} }

func (k *CaptureWcard4) DeepCopyMapKey() bpf.MapKey {
	return &CaptureWcard4{
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

func (k *CaptureWcard4) Dump(sb *strings.Builder) {
	sb.WriteString(fmt.Sprintf("%s/%d:%d -> %s/%d:%d %s ",
		k.SrcAddr,
		int(k.SrcMask),
		k.SrcPort,
		k.DestAddr,
		int(k.DestMask),
		k.DestPort,
		u8proto.U8proto(k.NextHdr)))
}

func (k *CaptureWcard4) String() string {
	var sb strings.Builder

	k.ToHost().Dump(&sb)
	return sb.String() + "\n"
}

func (k *CaptureWcard4) ToHost() RecorderKey {
	x := *k
	x.DestPort = byteorder.NetworkToHost(k.DestPort).(uint16)
	x.SrcPort = byteorder.NetworkToHost(k.SrcPort).(uint16)
	return &x
}

func (k *CaptureWcard4) Map() *bpf.Map {
	return &CaptureMap4.Map
}

func (v *CaptureRule4) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

func (v *CaptureRule4) DeepCopyMapValue() bpf.MapValue {
	return &CaptureRule4{
		RuleId:   v.RuleId,
		Reserved: v.Reserved,
		CapLen:   v.CapLen,
	}
}

func (v *CaptureRule4) Dump(sb *strings.Builder) {
	sb.WriteString(fmt.Sprintf("ID:%d CapLen:%d\n",
		int(v.RuleId),
		int(v.CapLen)))
}

func (v *CaptureRule4) String() string {
	var sb strings.Builder

	v.Dump(&sb)
	return sb.String()
}

var CaptureMap4 = &Map{
	Map: *bpf.NewMap(
		MapNameWcard4,
		bpf.MapTypeHash,
		&CaptureWcard4{}, int(unsafe.Sizeof(CaptureWcard4{})),
		&CaptureRule4{}, int(unsafe.Sizeof(CaptureRule4{})),
		MapSize,
		bpf.BPF_F_NO_PREALLOC, 0,
		bpf.ConvertKeyValue,
	).WithCache(),
	v4: true,
}
