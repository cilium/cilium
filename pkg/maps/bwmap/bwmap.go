// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bwmap

import (
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/option"
)

const (
	MapName = "cilium_throttle"
	// Flow aggregate is per Pod, so same size as Endpoint map.
	MapSize = lxcmap.MaxEntries

	// DefaultDropHorizon represents maximum allowed departure
	// time delta in future. Given applications can set SO_TXTIME
	// from user space this is a limit to prevent buggy applications
	// to fill the FQ qdisc.
	DefaultDropHorizon = 2 * time.Second
)

type EdtId struct {
	Id uint64 `align:"id"`
}

func (k *EdtId) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *EdtId) NewValue() bpf.MapValue     { return &EdtInfo{} }
func (k *EdtId) String() string             { return fmt.Sprintf("%d", int(k.Id)) }
func (k *EdtId) DeepCopyMapKey() bpf.MapKey { return &EdtId{k.Id} }

type EdtInfo struct {
	Bps             uint64    `align:"bps"`
	TimeLast        uint64    `align:"t_last"`
	TimeHorizonDrop uint64    `align:"t_horizon_drop"`
	Pad             [4]uint64 `align:"pad"`
}

func (v *EdtInfo) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *EdtInfo) String() string              { return fmt.Sprintf("%d", int(v.Bps)) }
func (v *EdtInfo) DeepCopyMapValue() bpf.MapValue {
	return &EdtInfo{v.Bps, v.TimeLast, v.TimeHorizonDrop, v.Pad}
}

var (
	throttleMap     *bpf.Map
	throttleMapInit = &sync.Once{}
)

func ThrottleMap() *bpf.Map {
	throttleMapInit.Do(func() {
		throttleMap = bpf.NewMap(
			MapName,
			bpf.MapTypeHash,
			&EdtId{}, int(unsafe.Sizeof(EdtId{})),
			&EdtInfo{}, int(unsafe.Sizeof(EdtInfo{})),
			MapSize,
			bpf.BPF_F_NO_PREALLOC,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(MapName))
	})

	return throttleMap
}

func Update(Id uint16, Bps uint64) error {
	return ThrottleMap().Update(
		&EdtId{Id: uint64(Id)},
		&EdtInfo{Bps: Bps, TimeHorizonDrop: uint64(DefaultDropHorizon)})
}

func Delete(Id uint16) error {
	return ThrottleMap().Delete(
		&EdtId{Id: uint64(Id)})
}

func SilentDelete(Id uint16) error {
	_, err := ThrottleMap().SilentDelete(
		&EdtId{Id: uint64(Id)})

	return err
}
