// Copyright 2016-2019 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/loadbalancer"
	"os"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/byteorder"

	"github.com/cilium/cilium/pkg/bpf"
)

var (
	MaglevRingMapName = "cilium_lb_maglev_ring"
	innerMapName      = "lb_maglev_ring_inner_map"
)

var (
	buildMap sync.Once
	closeMap sync.Once

	// MaglevRingMap is the global singleton of the maglev ring map.
	MaglevRingMap *bpf.Map
)

func convertMaglevKeyValue(key []byte, value []byte, mapKey bpf.MapKey, mapValue bpf.MapValue) (bpf.MapKey, bpf.MapValue, error) {
	ringKey, ringVal := mapKey.(*MaglevRingOuterKey), mapValue.(*MaglevRingOuterValue)

	if _, _, err := bpf.ConvertKeyValue(key, value, ringKey, ringVal); err != nil {
		return nil, nil, err
	}
	return ringKey.ToHost(), ringVal, nil
}

func newMaglevRingMap(mapName string, innerID uint32) *bpf.Map {
	return bpf.NewMap(
		mapName,
		bpf.MapTypeHashOfMaps,
		&MaglevRingOuterKey{},
		int(unsafe.Sizeof(MaglevRingOuterKey{})),
		&MaglevRingOuterValue{},
		int(unsafe.Sizeof(MaglevRingOuterValue{})),
		MaxEntries,
		0,
		innerID,
		convertMaglevKeyValue,
	).WithCache()
}

// CreateWithName creates a new outer maglev hash of maps for
// looking up an maglev ring map by the service id.
//
// The specified mapName allows non-standard map paths to be used, for instance
// for testing purposes.
func CreateWithName(mapName string) error {
	buildMap.Do(func() {
		fd, err := bpf.CreateMap(bpf.MapTypeArray,
			uint32(unsafe.Sizeof(MaglevRingKey{})),
			uint32(unsafe.Sizeof(MaglevRingValue{})),
			uint32(DefaultMaglevRingSize),
			0, 0, innerMapName)

		if err != nil {
			log.WithError(err).Warning("unable to create inner maglev ring map")
			return
		}
		MaglevRingMap = newMaglevRingMap(mapName, uint32(fd))
	})

	_, err := MaglevRingMap.OpenOrCreate()
	return err
}

// CloseMaglevRingMap will close the global maglev ring map
func CloseMaglevRingMap() {
	closeMap.Do(func() {
		if MaglevRingMap != nil {
			_ = MaglevRingMap.Close()
			MaglevRingMap = nil
		}
	})
}

// CreateMaglevRingMap will create both the innerMap (needed for map in map types) and
// then after BPFFS is mounted create the maglevRingMap. We only create the innerFd once
// to avoid having multiple inner maps.
func CreateMaglevRingMap() error {
	err := CreateWithName(MaglevRingMapName)
	if err != nil {
		log.WithError(err).Warning("Unable to open or create maglev ring map")
	}
	return err
}

func registerMaglevRingMap(m *bpf.Map, id uint16) error {
	return MaglevRingMap.Update((&MaglevRingOuterKey{Id: id}).ToNetwork(),
		&MaglevRingOuterValue{Fd: uint32(m.GetFd())})
}

func unregisterMaglevRingMap(id uint16) error {
	return MaglevRingMap.Delete((&MaglevRingOuterKey{Id: id}).ToNetwork())
}

func maglevRingInnerMapName(id uint16) string {
	return bpf.LocalMapPath(innerMapName+"_", id)
}

func newMaglevRingInnerMap(ringSize int, svcId uint16) *bpf.Map {
	return bpf.NewMap(
		maglevRingInnerMapName(svcId),
		bpf.MapTypeArray,
		&MaglevRingKey{},
		int(unsafe.Sizeof(MaglevRingKey{})),
		&MaglevRingValue{},
		int(unsafe.Sizeof(MaglevRingValue{})),
		ringSize,
		0,
		0,
		bpf.ConvertKeyValue,
	).WithCache()
}

func createMaglevRingInnerMap(ringSize int, svcId uint16) (*bpf.Map, error) {
	m := newMaglevRingInnerMap(ringSize, svcId)
	_, err := m.OpenOrCreateUnpinned()
	if err == nil {
		// init backend
		for i := 0; i < ringSize; i++ {
			_ = m.Update(&MaglevRingKey{Id: uint32(i)}, &MaglevRingValue{BackendID: -1})
		}
	}
	return m, err
}

func recoverMaglevRingInnerMap(ringSize, mapId int, id uint16) (*bpf.Map, error) {
	m, err := bpf.NewMapFromID(
		maglevRingInnerMapName(id),
		bpf.MapTypeArray,
		&MaglevRingKey{},
		int(unsafe.Sizeof(MaglevRingKey{})),
		&MaglevRingValue{},
		int(unsafe.Sizeof(MaglevRingValue{})),
		ringSize,
		0,
		0,
		mapId,
		false,
		bpf.ConvertKeyValue)
	if err != nil {
		return nil, fmt.Errorf("MapFdFromID id %v error: %v", mapId, err)
	}
	return m.WithCache(), nil
}

func lookupMaglevRingInnerMap(ringSize int, id uint16) (*bpf.Map, error) {
	// try to lookup cache
	name := bpf.MapPath(maglevRingInnerMapName(id))
	if m := bpf.GetMap(name); m != nil {
		return m, nil
	}

	// try to lookup outer map
	key := (&MaglevRingOuterKey{Id: id}).ToNetwork()
	if value, err := MaglevRingMap.Lookup(key); err == nil {
		return recoverMaglevRingInnerMap(ringSize, int(value.(*MaglevRingOuterValue).Fd), id)
	}
	return nil, nil
}

func closeMaglevRingInnerMap(m *bpf.Map, svcId uint16) {
	_ = m.Close()
}

// MaglevEnabled returns true if maglev ring map exists in bpffs
func MaglevEnabled() bool {
	path, err := newMaglevRingMap(MaglevRingMapName, 0).Path()
	if err == nil {
		if _, err = os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

// AppendMaglevInfo appends maglev related info to serviceList
func AppendMaglevInfo(serviceList map[string][]string, svcIdMap map[string]uint16,
	backendMap map[loadbalancer.BackendID]BackendValue, ringSize int) {

	svcMap := make(map[uint16]*bpf.Map)
	outerMap := newMaglevRingMap(MaglevRingMapName, 0)
	if err := outerMap.DumpWithCallbackIfExists(func(key bpf.MapKey, value bpf.MapValue) {
		svcID := key.(*MaglevRingOuterKey).Id
		mapID := value.(*MaglevRingOuterValue).Fd
		m, e := recoverMaglevRingInnerMap(ringSize, int(mapID), svcID)
		if e != nil {
			log.WithError(e).Warningf("unable to recover maglev ring map map_id %v id %v", mapID, svcID)
			return
		}
		svcMap[svcID] = m
	}); err != nil {
		return
	}

	for svc, id := range svcIdMap {
		m, ok := svcMap[id]
		if !ok {
			serviceList[svc] = append(serviceList[svc], fmt.Sprintf("svc %d not found", id))
			continue
		}

		// check first value
		value, err := m.Lookup(&MaglevRingKey{Id: 0})
		if err != nil {
			log.WithError(err).Warningf("svc %s map Lookup key 0", svc)
			serviceList[svc] = append(serviceList[svc], fmt.Sprintf("svc %d not found: %v", id, err))
			continue
		}
		backendValue := value.(*MaglevRingValue)
		if !backendValue.IsInvalid() {
			// range all backends, this may be very slow
			backendFreq := make(map[int32]int)
			if err := m.DumpWithCallback(func(key bpf.MapKey, value bpf.MapValue) {
				backendValue := value.(*MaglevRingValue)
				if backendValue.IsInvalid() {
					return
				}
				backendID := backendValue.BackendID
				if _, ok := backendFreq[backendID]; ok {
					backendFreq[backendID]++
				} else {
					backendFreq[backendID] = 1
				}
			}); err != nil {
				serviceList[svc] = append(serviceList[svc],
					fmt.Sprintf("svc %d not found: %v", id, err))
				continue
			}

			// fill backends maglev info
			for backendID, freq := range backendFreq {
				if backend, ok := backendMap[loadbalancer.BackendID(backendID)]; ok {
					serviceList[svc] = append(serviceList[svc],
						fmt.Sprintf("%s:%d (%d) [%d]",
							backend.GetAddress(), backend.GetPort(), id, freq))
					continue
				}
				serviceList[svc] = append(serviceList[svc], fmt.Sprintf("backend %d not found [maglev]", backendID))
			}
		}

		if len(serviceList[svc]) == 1 {
			serviceList[svc] = append(serviceList[svc], fmt.Sprintf("no backends for %d", id))
		}
	}
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type MaglevRingOuterKey struct {
	Id uint16
}

// ToNetwork returns the network byte order of the outer key
func (v *MaglevRingOuterKey) ToNetwork() *MaglevRingOuterKey {
	n := *v
	n.Id = byteorder.HostToNetwork(n.Id).(uint16)
	return &n
}

// ToHost returns the host byte order of the outer key
func (v *MaglevRingOuterKey) ToHost() *MaglevRingOuterKey {
	n := *v
	n.Id = byteorder.NetworkToHost(n.Id).(uint16)
	return &n
}

// String returns the key info
func (v MaglevRingOuterKey) String() string { return fmt.Sprintf("id=%d", v.Id) }

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *MaglevRingOuterKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// NewValue returns a new empty instance of the Endpoint Policy fd
func (k MaglevRingOuterKey) NewValue() bpf.MapValue { return &MaglevRingOuterValue{} }

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type MaglevRingOuterValue struct {
	Fd uint32
}

// String returns the value info
func (v MaglevRingOuterValue) String() string { return fmt.Sprintf("fd=%d", v.Fd) }

// GetValuePtr returns the unsafe value pointer to the fd
func (v *MaglevRingOuterValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type MaglevRingKey struct {
	Id uint32
}

// String returns the key info
func (v MaglevRingKey) String() string { return fmt.Sprintf("id=%d", v.Id) }

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *MaglevRingKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// NewValue returns a new empty instance of the Endpoint Policy fd
func (k MaglevRingKey) NewValue() bpf.MapValue { return &MaglevRingValue{} }

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type MaglevRingValue struct {
	BackendID int32
}

// String returns the value info
func (v MaglevRingValue) String() string { return fmt.Sprintf("backend_id=%d", v.BackendID) }

// GetValuePtr returns the unsafe value pointer to the fd
func (v *MaglevRingValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// IsInvalid returns true if the backendID <= 0
func (v *MaglevRingValue) IsInvalid() bool { return v.BackendID <= 0 }
