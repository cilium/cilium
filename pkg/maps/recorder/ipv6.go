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
type CaptureWcard6 recorderTypes.CaptureWcard6

type CaptureRule6 CaptureRule

func (k *CaptureWcard6) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

func (k *CaptureWcard6) NewValue() bpfTypes.MapValue { return &CaptureRule6{} }

func (k *CaptureWcard6) DeepCopyMapKey() bpfTypes.MapKey {
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

func (v *CaptureRule6) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

func (v *CaptureRule6) DeepCopyMapValue() bpfTypes.MapValue {
	return &CaptureRule6{
		RuleId:   v.RuleId,
		Reserved: v.Reserved,
		CapLen:   v.CapLen,
	}
}

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
				bpf.MapTypeHash,
				&CaptureWcard6{}, int(unsafe.Sizeof(CaptureWcard6{})),
				&CaptureRule6{}, int(unsafe.Sizeof(CaptureRule6{})),
				MapSize,
				bpf.BPF_F_NO_PREALLOC, 0,
				bpf.ConvertKeyValue,
			).WithCache().WithEvents(option.Config.GetEventBufferConfig(MapNameWcard6)),
			v4: false,
		}
	})
	return captureMap6
}
