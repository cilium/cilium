// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/ebpf"
)

// compile time check of MapV2 interface
var _ MapV2 = (*nodeMapV2)(nil)

const (
	MapNameV2 = "cilium_node_map_v2"
)

// MapV2 provides access to the eBPF map node.
//
// MapV2 will mirror all writes into MapV1.
type MapV2 interface {
	// Update inserts or updates the node map object associated with the provided
	// IP, node id, and SPI.
	Update(ip net.IP, nodeID uint16, SPI uint8) error

	// Delete deletes the node map object associated with the provided
	// IP.
	Delete(ip net.IP) error

	// IterateWithCallback iterates through all the keys/values of a node map,
	// passing each key/value pair to the cb callback.
	IterateWithCallback(cb NodeIterateCallbackV2) error

	// Size returns what how many entries the node map is configured to hold.
	Size() uint32
}

// nodeMapV2 is an iteration on nodeMap which associates an IPSec SPI with each
// node in the map.
type nodeMapV2 struct {
	conf   Config
	bpfMap *ebpf.Map
	v1Map  *nodeMap
}

func newMapV2(mapName string, v1MapName string, conf Config) *nodeMapV2 {
	v1Map := newMap(v1MapName, conf)

	if err := v1Map.init(); err != nil {
		log.WithError(err).Error("failed to init v1 node map")
		return nil
	}

	return &nodeMapV2{
		conf:  conf,
		v1Map: v1Map,
		bpfMap: ebpf.NewMap(&ebpf.MapSpec{
			Name:       mapName,
			Type:       ebpf.Hash,
			KeySize:    uint32(unsafe.Sizeof(NodeKey{})),
			ValueSize:  uint32(unsafe.Sizeof(NodeValueV2{})),
			MaxEntries: conf.NodeMapMax,
			Flags:      unix.BPF_F_NO_PREALLOC,
			Pinning:    ebpf.PinByName,
		}),
	}
}

type NodeValueV2 struct {
	NodeID uint16
	SPI    uint8
	Pad    uint8
}

func (m *nodeMapV2) Update(ip net.IP, nodeID uint16, SPI uint8) error {
	key := newNodeKey(ip)
	val := NodeValueV2{NodeID: nodeID, SPI: SPI}
	if err := m.bpfMap.Update(key, val, 0); err != nil {
		return fmt.Errorf("failed to update node map: %w", err)
	}

	// mirror write
	if err := m.v1Map.Update(ip, nodeID); err != nil {
		return fmt.Errorf("failed to mirror write to v1 node map: %w", err)
	}

	return nil
}

func (m *nodeMapV2) Size() uint32 {
	return m.conf.NodeMapMax
}

func (m *nodeMapV2) Delete(ip net.IP) error {
	key := newNodeKey(ip)
	if err := m.bpfMap.Delete(key); err != nil {
		return fmt.Errorf("failed to delete node map: %w", err)
	}

	// mirror write
	if err := m.v1Map.Delete(ip); err != nil {
		return fmt.Errorf("failed to mirror delete to v1 node map: %w", err)
	}

	return nil
}

// NodeIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of a node map.
type NodeIterateCallbackV2 func(*NodeKey, *NodeValueV2)

func (m *nodeMapV2) IterateWithCallback(cb NodeIterateCallbackV2) error {
	return m.bpfMap.IterateWithCallback(&NodeKey{}, &NodeValueV2{},
		func(k, v interface{}) {
			key, ok := k.(*NodeKey)
			if !ok {
				log.WithField("key", k).Error("failed to cast key to NodeKey")
				return
			}
			value, ok := v.(*NodeValueV2)
			if !ok {
				log.WithField("value", v).Error("failed to cast value to NodeValueV2")
				return
			}

			cb(key, value)
		})
}

// LoadNodeMap loads the pre-initialized node map for access.
// This should only be used from components which aren't capable of using hive - mainly the Cilium CLI.
// It needs to initialized beforehand via the Cilium Agent.
func LoadNodeMapV2() (MapV2, error) {
	bpfMap, err := ebpf.LoadRegisterMap(MapNameV2)
	if err != nil {
		return nil, fmt.Errorf("failed to load bpf map: %w", err)
	}

	return &nodeMapV2{bpfMap: bpfMap}, nil
}

func (m *nodeMapV2) init() error {
	if err := m.bpfMap.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}

	return nil
}

func (m *nodeMapV2) close() error {
	if err := m.bpfMap.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}

	return nil
}
