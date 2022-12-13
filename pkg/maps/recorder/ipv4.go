// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package recorder

import (
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	bpfTypes "github.com/cilium/cilium/pkg/bpf/types"
	"github.com/cilium/cilium/pkg/byteorder"
	recorderTypes "github.com/cilium/cilium/pkg/maps/recorder/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/u8proto"
)

// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf/types.MapKey
type CaptureWcard4 recorderTypes.CaptureWcard4

type CaptureRule4 CaptureRule

func (k *CaptureWcard4) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

func (k *CaptureWcard4) NewValue() bpfTypes.MapValue { return &CaptureRule4{} }

func (k *CaptureWcard4) DeepCopyMapKey() bpfTypes.MapKey {
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
	x.DestPort = byteorder.NetworkToHost16(k.DestPort)
	x.SrcPort = byteorder.NetworkToHost16(k.SrcPort)
	return &x
}

func (k *CaptureWcard4) Map() *bpf.Map {
	return &CaptureMap4().Map
}

func (v *CaptureRule4) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

func (v *CaptureRule4) DeepCopyMapValue() bpfTypes.MapValue {
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

var (
	captureMap4         *Map
	captureMap4InitOnce = &sync.Once{}
)

func CaptureMap4() *Map {
	captureMap4InitOnce.Do(func() {
		captureMap4 = &Map{
			Map: *bpf.NewMap(
				MapNameWcard4,
				bpf.MapTypeHash,
				&CaptureWcard4{}, int(unsafe.Sizeof(CaptureWcard4{})),
				&CaptureRule4{}, int(unsafe.Sizeof(CaptureRule4{})),
				MapSize,
				bpf.BPF_F_NO_PREALLOC, 0,
				bpf.ConvertKeyValue,
			).WithCache().WithEvents(option.Config.GetEventBufferConfig(MapNameWcard4)),
			v4: true,
		}
	})
	return captureMap4
}
