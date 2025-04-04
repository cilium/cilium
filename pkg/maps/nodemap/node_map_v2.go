// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"unsafe"

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
	logger *slog.Logger
	conf   Config
	bpfMap *ebpf.Map
	v1Map  *nodeMap
}

func newMapV2(logger *slog.Logger, mapName string, v1MapName string, conf Config) *nodeMapV2 {
	v1Map := newMap(logger, v1MapName, conf)

	if err := v1Map.init(); err != nil {
		logger.Error("failed to init v1 node map", logfields.Error, err)
		return nil
	}

	return &nodeMapV2{
		logger: logger,
		conf:   conf,
		v1Map:  v1Map,
		bpfMap: ebpf.NewMap(logger, &ebpf.MapSpec{
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
		func(k, v any) {
			key, ok := k.(*NodeKey)
			if !ok {
				m.logger.Error(
					"failed to cast key to NodeKey",
					logfields.Key, k,
				)
				return
			}
			value, ok := v.(*NodeValueV2)
			if !ok {
				m.logger.Error(
					"failed to cast value to NodeValueV2",
					logfields.Value, k,
				)
				return
			}

			cb(key, value)
		})
}

// LoadNodeMap loads the pre-initialized node map for access.
// This should only be used from components which aren't capable of using hive - mainly the Cilium CLI.
// It needs to initialized beforehand via the Cilium Agent.
func LoadNodeMapV2(logger *slog.Logger) (MapV2, error) {
	bpfMap, err := ebpf.LoadRegisterMap(logger, MapNameV2)
	if err != nil {
		return nil, fmt.Errorf("failed to load bpf map: %w", err)
	}

	return &nodeMapV2{bpfMap: bpfMap}, nil
}

// migrateV1 will migrate the v1 NodeMap to this NodeMapv2
//
// Ensure this always occurs BEFORE we begin handling K8s Node events or else
// both this migration and the node events will be writing to the map.
//
// This migration will leave the v1 NodeMap preset on the filesystem.
// This is due to some unfortunately versioning requirements which forced this
// migration to occur within a patch release.
//
// When Cilium reaches v1.17 the v1 NodeMap will no longer be required and we
// can unpin the map after migration.
func (m *nodeMapV2) migrateV1(NodeMapName string, EncryptMapName string) error {
	m.logger.Debug("Detecting V1 to V2 migration")

	// load v1 node map
	nodeMapPath := bpf.MapPath(NodeMapName)
	v1, err := ebpf.LoadPinnedMap(m.logger, nodeMapPath)
	if errors.Is(err, unix.ENOENT) {
		m.logger.Debug("No v1 node map found, skipping migration")
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
	en, err := ebpf.LoadPinnedMap(m.logger, encryptMapPath)
	if errors.Is(err, unix.ENOENT) {
		m.logger.Debug("No encrypt map found, skipping migration")
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
	count := 0
	parse := func(k *NodeKey, v *NodeValue) {
		v2 := NodeValueV2{
			NodeID: v.NodeID,
			SPI:    SPI,
		}
		count++
		m.bpfMap.Put(k, &v2)
	}

	m.logger.Debug(
		"Migrated V1 node map entries to V2",
		logfields.SPI, SPI,
		logfields.Entries, count,
	)

	err = nodeMap.IterateWithCallback(parse)
	if err != nil {
		return fmt.Errorf("failed to iterate v1 node map %w", err)
	}

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
