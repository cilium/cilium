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

func (k *CaptureWcard4) New() bpf.MapKey { return &CaptureWcard4{} }

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
	x.DestPort = byteorder.NetworkToHost16(k.DestPort)
	x.SrcPort = byteorder.NetworkToHost16(k.SrcPort)
	return &x
}

func (k *CaptureWcard4) Map() *bpf.Map {
	return &CaptureMap4().Map
}

func (v *CaptureRule4) New() bpf.MapValue { return &CaptureRule4{} }

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

var (
	captureMap4         *Map
	captureMap4InitOnce = &sync.Once{}
)

func CaptureMap4() *Map {
	captureMap4InitOnce.Do(func() {
		captureMap4 = &Map{
			Map: *bpf.NewMap(
				MapNameWcard4,
				ebpf.Hash,
				&CaptureWcard4{},
				&CaptureRule4{},
				MapSize,
				bpf.BPF_F_NO_PREALLOC,
			).WithCache().WithEvents(option.Config.GetEventBufferConfig(MapNameWcard4)),
			v4: true,
		}
	})
	return captureMap4
}
