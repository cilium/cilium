// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package egressmap

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
)

// EgressCtKey4 is the key of an egress CT map.
type EgressCtKey4 struct {
	tuple.TupleKey4
}

// EgressCtVal is the value of an egress CT map.
type EgressCtVal4 struct {
	Gateway types.IPv4
}

// egressCtMap is the internal representation of an egress CT map.
type egressCtMap struct {
	*ebpf.Map
}

// initEgressCtMap initializes the egress CT map.
func initEgressCtMap(ctMapName string, create bool) error {
	var m *ebpf.Map

	if create {
		m = ebpf.NewMap(&ebpf.MapSpec{
			Name:       ctMapName,
			Type:       ebpf.LRUHash,
			KeySize:    uint32(unsafe.Sizeof(EgressCtKey4{})),
			ValueSize:  uint32(unsafe.Sizeof(EgressCtVal4{})),
			MaxEntries: uint32(MaxCtEntries),
			Pinning:    ebpf.PinByName,
		})

		if err := m.OpenOrCreate(); err != nil {
			return err
		}
	} else {
		var err error
		if m, err = ebpf.OpenMap(ctMapName); err != nil {
			return err
		}
	}

	EgressCtMap = &egressCtMap{
		m,
	}

	return nil
}

// removeCtEntries removes all CT entries from the egress CT map matching the
// (source IP, destination CIDR, gateway IP) tuple.
func removeCtEntries(sourceIP net.IP, destCIDR net.IPNet, gatewayIP net.IP) error {
	keysToDelete := []EgressCtKey4{}

	err := EgressCtMap.IterateWithCallback(
		func(ctKey *EgressCtKey4, ctVal *EgressCtVal4) {
			if ctKey.SourceAddr.IP().Equal(sourceIP) &&
				destCIDR.Contains(ctKey.DestAddr.IP()) &&
				ctVal.Gateway.IP().Equal(gatewayIP) {

				// It's not safe to delete an element from a hashmap
				// while iterating it. Store the keys and delete them
				// once we are done iterating.
				keysToDelete = append(keysToDelete, *ctKey)
			}
		})

	if err != nil {
		return fmt.Errorf("error while iterating egress CT map: %s", err)
	}

	for _, k := range keysToDelete {
		if err := EgressCtMap.Delete(k); err != nil {
			log.Errorf("Cannot remove egress CT entry: %s", err)
		}
	}

	return nil
}

// EgressCtIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an egress CT map.
type EgressCtIterateCallback func(*EgressCtKey4, *EgressCtVal4)

// IterateWithCallback iterates through all the keys/values of an egress CT map,
// passing each key/value pair to the cb callback.
func (m egressCtMap) IterateWithCallback(cb EgressCtIterateCallback) error {
	return m.Map.IterateWithCallback(&EgressCtKey4{}, &EgressCtVal4{},
		func(k, v interface{}) {
			key := k.(*EgressCtKey4)
			value := v.(*EgressCtVal4)

			cb(key, value)
		})
}
