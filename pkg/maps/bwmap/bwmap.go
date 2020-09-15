// Copyright 2020 Authors of Cilium
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

package bwmap

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
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

var ThrottleMap = bpf.NewMap(
	MapName,
	bpf.MapTypeHash,
	&EdtId{}, int(unsafe.Sizeof(EdtId{})),
	&EdtInfo{}, int(unsafe.Sizeof(EdtInfo{})),
	MapSize,
	bpf.BPF_F_NO_PREALLOC, 0,
	bpf.ConvertKeyValue,
).WithCache()

func Update(Id uint16, Bps uint64) error {
	return ThrottleMap.Update(
		&EdtId{Id: uint64(Id)},
		&EdtInfo{Bps: Bps, TimeHorizonDrop: uint64(DefaultDropHorizon)})
}

func Delete(Id uint16) error {
	return ThrottleMap.Delete(
		&EdtId{Id: uint64(Id)})
}
