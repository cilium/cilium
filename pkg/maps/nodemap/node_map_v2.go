// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// compile time check of MapV2 interface
var _ MapV2 = (*nodeMapV2)(nil)

const (
	MapNameV2 = "cilium_node_map_v2"
)

// Map provides access to the eBPF map node.
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
}

func newMapV2(mapName string, conf Config) *nodeMapV2 {
	return &nodeMapV2{
		conf: conf,
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
	return m.bpfMap.Update(key, val, 0)
}

func (m *nodeMapV2) Size() uint32 {
	return m.conf.NodeMapMax
}

func (m *nodeMapV2) Delete(ip net.IP) error {
	key := newNodeKey(ip)
	return m.bpfMap.Map.Delete(key)
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

// migrateV1 will migrate the v1 NodeMap to this NodeMapv2
//
// Ensure this always occurs BEFORE we begin handling K8s Node events or else
// both this migration and the node events will be writing to the map.
func (m *nodeMapV2) migrateV1(NodeMapName string, EncryptMapName string) error {
	log.Debug("Detecting V1 to V2 migration")

	// load v1 node map
	nodeMapPath := bpf.MapPath(NodeMapName)
	v1, err := ebpf.LoadPinnedMap(nodeMapPath)
	if errors.Is(err, unix.ENOENT) {
		log.Debug("No v1 node map found, skipping migration")
		return nil
	}
	if err != nil {
		return err
	}
	nodeMap := nodeMap{
		bpfMap: v1,
	}

	// load encrypt map to get current SPI
	encryptMapPath := bpf.MapPath(EncryptMapName)
	en, err := ebpf.LoadPinnedMap(encryptMapPath)
	if errors.Is(err, unix.ENOENT) {
		log.Debug("No encrypt map found, skipping migration")
		return nil
	}
	if err != nil {
		return err
	}
	defer en.Close()

	var SPI uint8
	if err = en.Lookup(uint32(0), &SPI); err != nil {
		return err
	}

	// reads v1 map entries and writes them to V2 with the latest SPI found
	// from EncryptMap
	parse := func(k *NodeKey, v *NodeValue) {
		v2 := NodeValueV2{
			NodeID: v.NodeID,
			SPI:    SPI,
		}

		log.WithFields(logrus.Fields{
			logfields.NodeID: v2.NodeID,
			logfields.IPAddr: k.IP,
			logfields.SPI:    v2.SPI,
		}).Debug("Migrating V1 node map entry to V2")

		m.bpfMap.Put(k, &v2)
	}

	err = nodeMap.IterateWithCallback(parse)
	if err != nil {
		return fmt.Errorf("failed to iterate v1 node map %w", err)
	}

	// migration was successful so close and unpin the v1 NodeMap
	v1.Close()
	v1.Unpin()

	return nil
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
