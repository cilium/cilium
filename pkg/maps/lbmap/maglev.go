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

package lbmap

import (
	"fmt"
	"io"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

const (
	// Both inner maps are not being pinned into BPF fs.
	MaglevInner4MapName = "cilium_lb4_maglev_inner"
	MaglevInner6MapName = "cilium_lb6_maglev_inner"

	// Both outer maps are pinned though given we need to attach
	// inner maps into them.
	MaglevOuter4MapName = "cilium_lb4_maglev"
	MaglevOuter6MapName = "cilium_lb6_maglev"
)

var MaglevOuter4Map *bpf.Map
var MaglevOuter6Map *bpf.Map

func InitMaglevMaps(ipv4 bool, ipv6 bool) error {
	dummyInnerMap := newInnerMaglevMap("cilium_lb_maglev_dummy")
	if err := dummyInnerMap.CreateUnpinned(); err != nil {
		return err
	}
	defer dummyInnerMap.Close()

	if ipv4 {
		if _, err := deleteMapIfMNotMatch(MaglevOuter4MapName); err != nil {
			return err
		}
		MaglevOuter4Map = newOuterMaglevMap(MaglevOuter4MapName, dummyInnerMap)
		if _, err := MaglevOuter4Map.OpenOrCreate(); err != nil {
			return err
		}
	}
	if ipv6 {
		if _, err := deleteMapIfMNotMatch(MaglevOuter6MapName); err != nil {
			return err
		}
		MaglevOuter6Map = newOuterMaglevMap(MaglevOuter6MapName, dummyInnerMap)
		if _, err := MaglevOuter6Map.OpenOrCreate(); err != nil {
			return err
		}
	}

	return nil
}

// deleteMapIfMNotMatch removes the outer maglev maps if the M param
// (MaglevTableSize) has changed. This is to avoid the verifier error when
// loading BPF programs which access the maps.
func deleteMapIfMNotMatch(mapName string) (bool, error) {
	deleteMap := false

	m, err := bpf.OpenMap(mapName)
	if err == nil {
		outerKey := &MaglevOuterKey{}
		if err := bpf.GetNextKey(m.GetFd(), nil, unsafe.Pointer(outerKey)); err == nil {
			outerVal, err := m.Lookup(outerKey)
			if err != nil {
				return false, err
			}
			v := outerVal.(*MaglevOuterVal)

			fd, err := bpf.MapFdFromID(int(v.FD))
			if err != nil {
				return false, err
			}
			info, err := bpf.GetMapInfoByFd(uint32(fd))
			if err != nil {
				return false, err
			}
			previousM := int(info.ValueSize) / int(unsafe.Sizeof(uint16(0)))
			if option.Config.MaglevTableSize != previousM {
				deleteMap = true
			}
		} else if err == io.EOF {
			// The map is empty. To be on the safe side, remove it to avoid M
			// mismatch. The removal is harmless, as no new entry can be
			// created while the initialization of the map has not returned.
			deleteMap = true
		} else {
			return false, err
		}
	}

	if deleteMap {
		log.WithField(logfields.BPFMapName, mapName).
			Info("Deleting Maglev outer map due to different M or empty map")
		if err := m.Unpin(); err != nil {
			return false, err
		}
	}

	return deleteMap, nil
}

func newInnerMaglevMap(name string) *bpf.Map {
	return bpf.NewMapWithOpts(
		name,
		bpf.MapTypeArray,
		&MaglevInnerKey{}, int(unsafe.Sizeof(MaglevInnerKey{})),
		&MaglevInnerVal{}, int(unsafe.Sizeof(uint16(0)))*option.Config.MaglevTableSize,
		1, 0, 0,
		bpf.ConvertKeyValue,
		&bpf.NewMapOpts{},
	)
}

func newOuterMaglevMap(name string, innerMap *bpf.Map) *bpf.Map {
	return bpf.NewMap(
		name,
		bpf.MapTypeHashOfMaps,
		&MaglevOuterKey{}, int(unsafe.Sizeof(MaglevOuterKey{})),
		&MaglevOuterVal{}, int(unsafe.Sizeof(MaglevOuterVal{})),
		MaxEntries,
		0, uint32(innerMap.GetFd()),
		bpf.ConvertKeyValue,
	)
}

func updateMaglevTable(ipv6 bool, revNATID uint16, backendIDs []uint16) error {
	outerMap := MaglevOuter4Map
	innerMapName := MaglevInner4MapName
	if ipv6 {
		outerMap = MaglevOuter6Map
		innerMapName = MaglevInner6MapName
	}

	innerMap := newInnerMaglevMap(innerMapName)
	if err := innerMap.CreateUnpinned(); err != nil {
		return err
	}
	defer innerMap.Close()

	innerKey := &MaglevInnerKey{Zero: 0}
	innerVal := &MaglevInnerVal{BackendIDs: backendIDs}
	if err := innerMap.Update(innerKey, innerVal); err != nil {
		return err
	}

	outerKey := (&MaglevOuterKey{RevNatID: revNATID}).ToNetwork()
	outerVal := &MaglevOuterVal{FD: uint32(innerMap.GetFd())}
	if err := outerMap.Update(outerKey, outerVal); err != nil {
		return err
	}

	return nil
}

func deleteMaglevTable(ipv6 bool, revNATID uint16) error {
	outerMap := MaglevOuter4Map
	if ipv6 {
		outerMap = MaglevOuter6Map
	}

	outerKey := (&MaglevOuterKey{RevNatID: revNATID}).ToNetwork()
	if err := outerMap.Delete(outerKey); err != nil {
		return err
	}

	return nil
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type MaglevInnerKey struct{ Zero uint32 }

func (k *MaglevInnerKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *MaglevInnerKey) NewValue() bpf.MapValue    { return &MaglevInnerVal{} }
func (k *MaglevInnerKey) String() string            { return fmt.Sprintf("%d", k.Zero) }

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type MaglevInnerVal struct {
	BackendIDs []uint16
}

func (v *MaglevInnerVal) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(&v.BackendIDs[0]) }
func (v *MaglevInnerVal) String() string              { return fmt.Sprintf("%v", v.BackendIDs) }

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type MaglevOuterKey struct{ RevNatID uint16 }

func (k *MaglevOuterKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *MaglevOuterKey) NewValue() bpf.MapValue    { return &MaglevOuterVal{} }
func (k *MaglevOuterKey) String() string            { return fmt.Sprintf("%d", k.RevNatID) }
func (k *MaglevOuterKey) ToNetwork() *MaglevOuterKey {
	n := *k
	// For some reasons rev_nat_index is stored in network byte order in
	// the SVC BPF maps
	n.RevNatID = byteorder.HostToNetwork(n.RevNatID).(uint16)
	return &n
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type MaglevOuterVal struct{ FD uint32 }

func (v *MaglevOuterVal) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *MaglevOuterVal) String() string              { return fmt.Sprintf("%d", v.FD) }
