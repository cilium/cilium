// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

const (
	// Both outer maps are pinned though given we need to insert
	// inner maps into them.
	MaglevOuter4MapName = "cilium_lb4_maglev"
	MaglevOuter6MapName = "cilium_lb6_maglev"
)

var (
	maglevOuter4Map     *MaglevOuterMap
	maglevOuter6Map     *MaglevOuterMap
	maglevRecreatedIPv4 bool
	maglevRecreatedIPv6 bool
	maglevTableSize     uint32
)

// InitMaglevMaps inits the ipv4 and/or ipv6 maglev outer and inner maps.
func InitMaglevMaps(ipv4, ipv6 bool, tableSize uint32) error {
	// Always try to delete old maps with the wrong M parameter, otherwise
	// we may end up in a case where there are 2 maps (one for IPv4 and
	// one for IPv6), one of which is not used, with 2 different table
	// sizes.
	// This would confuse the MaybeInitMaglevMaps() function, which would
	// not be able to figure out the correct table size.
	r, err := deleteMapIfMNotMatch(MaglevOuter4MapName, tableSize)
	if err != nil {
		return err
	}
	maglevRecreatedIPv4 = r

	r, err = deleteMapIfMNotMatch(MaglevOuter6MapName, tableSize)
	if err != nil {
		return err
	}
	maglevRecreatedIPv6 = r

	dummyInnerMapSpec := newMaglevInnerMapSpec(tableSize)
	if ipv4 {
		outer, err := NewMaglevOuterMap(MaglevOuter4MapName, MaglevMapMaxEntries, tableSize, dummyInnerMapSpec)
		if err != nil {
			return err
		}
		maglevOuter4Map = outer
	}

	if ipv6 {
		outer, err := NewMaglevOuterMap(MaglevOuter6MapName, MaglevMapMaxEntries, tableSize, dummyInnerMapSpec)
		if err != nil {
			return err
		}
		maglevOuter6Map = outer
	}

	maglevTableSize = tableSize

	return nil
}

// deleteMapIfMNotMatch removes the outer maglev maps if it's a legacy map or
// the M param (MaglevTableSize) has changed. This is to avoid a verifier
// error when loading BPF programs which access the map.
func deleteMapIfMNotMatch(mapName string, tableSize uint32) (bool, error) {
	m, err := ebpf.LoadPinnedMap(bpf.MapPath(mapName))
	if errors.Is(err, os.ErrNotExist) {
		// No existing maglev outer map found.
		// Return true so the caller will create a new one.
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer m.Close()

	// Attempt to determine the outer map's table size.
	size, err := (&MaglevOuterMap{Map: m}).TableSize()
	if err == nil && size == tableSize {
		// An outer map with the correct table size already exists.
		// Return false as there no need to delete and recreate it.
		return false, nil
	}

	// An outer map already exists but it has the wrong table size (or we
	// can't determine it). Delete it.
	if err := m.Unpin(); err != nil {
		return false, fmt.Errorf("error unpinning existing outer map: %w", err)
	}

	return true, nil
}

// updateMaglevTable creates a new inner Maglev map containing the given backend IDs
// and sets it as the active lookup table for the given service ID.
func updateMaglevTable(ipv6 bool, revNATID uint16, backendIDs []loadbalancer.BackendID) error {
	outer := maglevOuter4Map
	if ipv6 {
		outer = maglevOuter6Map
	}

	if outer == nil {
		return errors.New("outer maglev maps not yet initialized")
	}

	inner, err := createMaglevInnerMap(maglevTableSize)
	if err != nil {
		return err
	}
	defer inner.Close()

	if err := inner.UpdateBackends(backendIDs); err != nil {
		return fmt.Errorf("updating backends: %w", err)
	}

	if err := outer.UpdateService(revNATID, inner); err != nil {
		return fmt.Errorf("updating service: %w", err)
	}

	return nil
}

// deleteMaglevTable deletes the inner Maglev lookup table for the given service ID.
func deleteMaglevTable(ipv6 bool, revNATID uint16) error {
	outerMap := maglevOuter4Map
	if ipv6 {
		outerMap = maglevOuter6Map
	}

	outerKey := MaglevOuterKey{RevNatID: revNATID}
	if err := outerMap.Delete(outerKey.toNetwork()); err != nil {
		return err
	}

	return nil
}
