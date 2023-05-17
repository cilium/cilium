// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MapName    = "cilium_node_map"
	MaxEntries = 16384
)

// Map provides access to the eBPF map node.
type Map interface {
	// Update inserts or updates the node map object associated with the provided
	// IP and node id.
	Update(ip net.IP, nodeID uint16) error

	// Delete deletes the node map object associated with the provided
	// IP.
	Delete(ip net.IP) error

	// IterateWithCallback iterates through all the keys/values of a node map,
	// passing each key/value pair to the cb callback.
	IterateWithCallback(cb NodeIterateCallback) error
}

type nodeMap struct {
	bpfMap *ebpf.Map
}

func newMap() *nodeMap {
	return &nodeMap{
		bpfMap: ebpf.NewMap(&ebpf.MapSpec{
			Name:       MapName,
			Type:       ebpf.Hash,
			KeySize:    uint32(unsafe.Sizeof(NodeKey{})),
			ValueSize:  uint32(unsafe.Sizeof(NodeValue{})),
			MaxEntries: uint32(MaxEntries),
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

type NodeValue struct {
	NodeID uint16
}

func (m *nodeMap) Update(ip net.IP, nodeID uint16) error {
	key := newNodeKey(ip)
	val := NodeValue{NodeID: nodeID}
	return m.bpfMap.Update(key, val, 0)
}

func (m *nodeMap) Delete(ip net.IP) error {
	key := newNodeKey(ip)
	return m.bpfMap.Map.Delete(key)
}

// NodeIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of a node map.
type NodeIterateCallback func(*NodeKey, *NodeValue)

func (m *nodeMap) IterateWithCallback(cb NodeIterateCallback) error {
	return m.bpfMap.IterateWithCallback(&NodeKey{}, &NodeValue{},
		func(k, v interface{}) {
			key := k.(*NodeKey)
			value := v.(*NodeValue)

			cb(key, value)
		})
}

// LoadNodeMap loads the pre-initialized node map for access.
// This should only be used from components which aren't capable of using hive - mainly the Cilium CLI.
// It needs to initialized beforehand via the Cilium Agent.
func LoadNodeMap() (Map, error) {
	bpfMap, err := ebpf.LoadRegisterMap(MapName)
	if err != nil {
		return nil, fmt.Errorf("failed to load bpf map: %w", err)
	}

	return &nodeMap{bpfMap: bpfMap}, nil
}

func (m *nodeMap) init() error {
	if err := m.bpfMap.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}

	return nil
}

func (m *nodeMap) close() error {
	if err := m.bpfMap.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}

	return nil
}
