// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package recorder

import (
	"fmt"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

type CaptureWcard6 struct {
	SrcAddr  types.IPv6 `align:"saddr"`
	DestAddr types.IPv6 `align:"daddr"`
	SrcPort  uint16     `align:"sport"`
	DestPort uint16     `align:"dport"`
	NextHdr  uint8      `align:"nexthdr"`
	SrcMask  uint8      `align:"smask"`
	DestMask uint8      `align:"dmask"`
	Flags    uint8      `align:"flags"`
}

type CaptureRule6 CaptureRule

func (k *CaptureWcard6) New() bpf.MapKey { return &CaptureWcard6{} }

func (k *CaptureWcard6) Dump(sb *strings.Builder) {
	sb.WriteString(fmt.Sprintf("[%s/%d]:%d -> [%s/%d]:%d %s ",
		k.SrcAddr,
		int(k.SrcMask),
		k.SrcPort,
		k.DestAddr,
		int(k.DestMask),
		k.DestPort,
		u8proto.U8proto(k.NextHdr)))
}

func (k *CaptureWcard6) String() string {
	var sb strings.Builder

	k.ToHost().Dump(&sb)
	return sb.String() + "\n"
}

func (k *CaptureWcard6) ToHost() RecorderKey {
	x := *k
	x.DestPort = byteorder.NetworkToHost16(k.DestPort)
	x.SrcPort = byteorder.NetworkToHost16(k.SrcPort)
	return &x
}

func (k *CaptureWcard6) Map() *bpf.Map {
	return &CaptureMap6().Map
}

func (v *CaptureRule6) New() bpf.MapValue { return &CaptureRule6{} }

func (v *CaptureRule6) Dump(sb *strings.Builder) {
	sb.WriteString(fmt.Sprintf("ID:%d CapLen:%d\n",
		int(v.RuleId),
		int(v.CapLen)))
}

func (v *CaptureRule6) String() string {
	var sb strings.Builder

	v.Dump(&sb)
	return sb.String()
}

var (
	captureMap6         *Map
	captureMap6InitOnce sync.Once
)

func CaptureMap6() *Map {
	captureMap6InitOnce.Do(func() {
		captureMap6 = &Map{
			Map: *bpf.NewMap(
				MapNameWcard6,
				ebpf.Hash,
				&CaptureWcard6{},
				&CaptureRule6{},
				MapSize,
				bpf.BPF_F_NO_PREALLOC,
			).WithCache().WithEvents(option.Config.GetEventBufferConfig(MapNameWcard6)),
			v4: false,
		}
	})
	return captureMap6
}
