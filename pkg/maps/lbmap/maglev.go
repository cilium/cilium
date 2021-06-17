// Copyright 2020-2021 Authors of Cilium
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
	"errors"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"

	"github.com/sirupsen/logrus"
)

const (
	// Both inner maps are not being pinned into BPF fs.
	MaglevInner4MapName = "cilium_lb4_maglev_inner"
	MaglevInner6MapName = "cilium_lb6_maglev_inner"

	// Both outer maps are pinned though given we need to attach
	// inner maps into them.
	MaglevOuter4MapName = "cilium_lb4_maglev"
	MaglevOuter6MapName = "cilium_lb6_maglev"

	// MaglevInnerElems is the number of backends stored inside each slot
	// (MaglevInnerKey) of the MaglevInnerVal.
	MaglevInnerElems = 4
)

var (
	maglevOuter4Map     *maglevOuterMap
	maglevOuter6Map     *maglevOuterMap
	maglevRecreatedIPv4 bool
	maglevRecreatedIPv6 bool
)

// InitMaglevMaps inits the ipv4 and/or ipv6 maglev outer and inner maps.
func InitMaglevMaps(ipv4, ipv6 bool, tableSize uint32) error {
	var err error

	dummyInnerMapSpec := newMaglevInnerMapSpec("cilium_lb_maglev_dummy", tableSize, true)

	// Always try to delete old maps with the wrong M parameter, otherwise
	// we may end up in a case where there are 2 maps (one for IPv4 and
	// one for IPv6), one of which is not used, with 2 different table
	// sizes.
	// This would confuse the MaybeInitMaglevMaps() function, which would
	// not be able to figure out the correct table size.
	if maglevRecreatedIPv4, err = deleteMapIfMNotMatch(MaglevOuter4MapName, tableSize); err != nil {
		return err
	}
	if maglevRecreatedIPv6, err = deleteMapIfMNotMatch(MaglevOuter6MapName, tableSize); err != nil {
		return err
	}

	if ipv4 {
		maglevOuter4Map, err = NewMaglevOuterMap(MaglevOuter4MapName, MaxEntries, tableSize, dummyInnerMapSpec)
		if err != nil {
			return err
		}
	}
	if ipv6 {
		maglevOuter6Map, err = NewMaglevOuterMap(MaglevOuter6MapName, MaxEntries, tableSize, dummyInnerMapSpec)
		if err != nil {
			return err
		}
	}

	return nil
}

// OpenMaglevMaps tries to open all already existing maglev BPF maps by
// probing their table size from the inner map value size.
func OpenMaglevMaps() (uint32, error) {
	var (
		detectedTableSize uint32
		err               error
	)

	map4Found, _, maglev4TableSize := MaglevMapInfo(MaglevOuter4MapName)
	map6Found, _, maglev6TableSize := MaglevMapInfo(MaglevOuter6MapName)

	switch {
	case !map4Found && !map6Found:
		return 0, nil
	case map4Found && maglev4TableSize == UnknownMaglevTableSize:
		return 0, errors.New("cannot determine v4 outer maglev map's table size")
	case map6Found && maglev6TableSize == UnknownMaglevTableSize:
		return 0, errors.New("cannot determine v6 outer maglev map's table size")
	case map4Found && map6Found && maglev4TableSize != maglev6TableSize:
		// Just being extra defensive here. This case should never
		// happen as both maps are created at the same time after
		// deleting eventual old maps with a different M parameter
		return 0, errors.New("v4 and v6 maps have different table sizes")
	case map4Found:
		detectedTableSize = maglev4TableSize
	case map6Found:
		detectedTableSize = maglev6TableSize
	}

	if map4Found {
		maglevOuter4Map, err = OpenMaglevOuterMap(MaglevOuter4MapName, detectedTableSize)
		if err != nil {
			return UnknownMaglevTableSize, err
		}
	}

	if map6Found {
		maglevOuter6Map, err = OpenMaglevOuterMap(MaglevOuter6MapName, detectedTableSize)
		if err != nil {
			return UnknownMaglevTableSize, err
		}
	}

	return detectedTableSize, nil
}

// GetOpenMaglevMaps returns a map with all the opened outer maglev eBPF maps.
// These BPF maps are indexed by their name.
func GetOpenMaglevMaps() map[string]*maglevOuterMap {
	maps := map[string]*maglevOuterMap{}
	if maglevOuter4Map != nil {
		maps[MaglevOuter4MapName] = maglevOuter4Map
	}
	if maglevOuter6Map != nil {
		maps[MaglevOuter6MapName] = maglevOuter6Map
	}

	return maps
}

// deleteMapIfMNotMatch removes the outer maglev maps if it's a legacy map or
// the M param (MaglevTableSize) has changed. This is to avoid the verifier
// error when loading BPF programs which access the maps.
func deleteMapIfMNotMatch(mapName string, tableSize uint32) (bool, error) {
	found, innerMap, prevTableSize := MaglevMapInfo(mapName)
	if !found {
		// No existing maglev outer map found.
		// Return true so the caller will create a new one.
		return true, nil
	}

	// An inner map already exists. We need to check if the map flags have
	// changed and if so, delete both the inner and outer map.
	if innerMap != nil {
		// Map name doesn't matter since we only care for the flags.
		if old, new := innerMap.Flags(), newMaglevInnerMapSpec("", prevTableSize, true).Flags; old != new {
			log.WithFields(logrus.Fields{
				"old": old,
				"new": new,
			}).Info("Found old Maglev inner map with mismatched flags. Both outer and inner maps will need to be deleted and recreated.")
			innerMap.Close()
			innerMap.Map.Unpin()
			goto deleteOuter
		}
	}

	if prevTableSize == tableSize {
		// An outer map with the correct table size already exists.
		// Return false as there no need to delete and recreate it.
		return false, nil
	}

deleteOuter:
	// An outer map already exists but it has the wrong table size (or we
	// can't determine it). Delete it.
	oldMap, err := ebpf.LoadPinnedMap(bpf.MapPath(mapName), nil)
	if err != nil {
		return false, err
	}
	oldMap.Unpin()

	return true, nil
}

func updateMaglevTable(ipv6 bool, revNATID uint16, backendIDs []uint16, tableSize uint64) error {
	outerMap := maglevOuter4Map
	innerMapName := MaglevInner4MapName
	if ipv6 {
		outerMap = maglevOuter6Map
		innerMapName = MaglevInner6MapName
	}

	innerMap, err := newMaglevInnerMap(innerMapName, uint32(tableSize), true)
	if err != nil {
		return err
	}
	defer innerMap.Close()

	if err := updateMaglevInnerMap(innerMap, backendIDs); err != nil {
		return err
	}

	outerKey := (&MaglevOuterKey{RevNatID: revNATID}).ToNetwork()
	outerVal := &MaglevOuterVal{FD: uint32(innerMap.FD())}
	if err := outerMap.Update(outerKey, outerVal); err != nil {
		return err
	}

	return nil
}

func updateMaglevInnerMap(m *maglevInnerMap, backendIDs []uint16) error {
	// We'll attempt to batch update if the kernel supports it. Batch ops are
	// supported from kernel version v5.6
	// (https://github.com/torvalds/linux/commit/aa2e93b8e58e18442edfb2427446732415bc215e).
	split := splitBackends(backendIDs)
	keys := make(maglevInnerKeys, len(split))
	vals := make(maglevInnerVals, len(split))
	for i := range split {
		keys[i] = &MaglevInnerKey{Slot: uint32(i)}
		vals[i] = &MaglevInnerVal{BackendIDs: split[i]}
	}
	_, err := m.BatchUpdate(keys, vals, nil)
	if err != nil && errors.Is(err, ebpf.ErrNotSupported) {
		// Fall back to updating the map one-by-one if batch ops are not
		// supported.
		for i := range split {
			if err := m.Update(keys[i], vals[i]); err != nil {
				return err
			}
		}
	}
	return err
}

func deleteMaglevTable(ipv6 bool, revNATID uint16) error {
	outerMap := maglevOuter4Map
	if ipv6 {
		outerMap = maglevOuter6Map
	}

	outerKey := (&MaglevOuterKey{RevNatID: revNATID}).ToNetwork()
	if err := outerMap.Delete(outerKey); err != nil {
		return err
	}

	return nil
}

// splitBackends splits the backends into chunks or slots so that they fit into
// MaglevInnerVal.
func splitBackends(b []uint16) [][MaglevInnerElems]uint16 {
	if b == nil {
		return nil
	}
	const size = MaglevInnerElems
	var chunk [size]uint16
	chunks := make([][size]uint16, 0, len(b)/size+1)
	for len(b) >= size {
		copy(chunk[:], b) // copies only min(len(chunk), len(b))
		b = b[size:]
		chunks = append(chunks, chunk)
	}
	if len(b) > 0 {
		var last [size]uint16
		copy(last[:], b)
		chunks = append(chunks, last)
	}
	return chunks
}
