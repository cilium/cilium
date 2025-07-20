// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/types"
)

// compile time check of MapV2 interface
var _ MapV2 = (*nodeMapV2)(nil)

const (
	MapNameV2         = "cilium_node_map_v2"
	DefaultMaxEntries = 16384
)

// MapV2 provides access to the eBPF map node.
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
}

func newMapV2(logger *slog.Logger, mapName string, conf Config) *nodeMapV2 {
	return &nodeMapV2{
		logger: logger,
		conf:   conf,
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

type NodeKey struct {
	Pad1   uint16 `align:"pad1"`
	Pad2   uint8  `align:"pad2"`
	Family uint8  `align:"family"`
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP types.IPv6 `align:"$union0"`
}

func (k *NodeKey) String() string {
	switch k.Family {
	case bpf.EndpointKeyIPv4:
		return net.IP(k.IP[:net.IPv4len]).String()
	case bpf.EndpointKeyIPv6:
		return k.IP.String()
	}
	return "<unknown>"
}

func newNodeKey(ip net.IP) NodeKey {
	result := NodeKey{}
	if ip4 := ip.To4(); ip4 != nil {
		result.Family = bpf.EndpointKeyIPv4
		copy(result.IP[:], ip4)
	} else {
		result.Family = bpf.EndpointKeyIPv6
		copy(result.IP[:], ip)
	}
	return result
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

// Clean up the v1 map. TODO remove this in v1.19.
func (m *nodeMapV2) migrateV1(NodeMapName string) {
	os.Remove(filepath.Join(bpf.TCGlobalsPath(), NodeMapName))
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
