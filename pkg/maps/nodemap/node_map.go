// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"net"
	"sync"
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

var (
	nodeMap     *Map
	nodeMapInit = &sync.Once{}
)

// SetNodeMap sets the node map. Only used for testing.
func SetNodeMap(m *Map) {
	nodeMap = m
}

func NodeMap() *Map {
	nodeMapInit.Do(func() {
		nodeMap = NewNodeMap(MapName)
	})
	return nodeMap
}

type Map struct {
	*ebpf.Map
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

func NewNodeMap(mapName string) *Map {
	return &Map{Map: ebpf.NewMap(&ebpf.MapSpec{
		Name:       mapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(NodeKey{})),
		ValueSize:  uint32(unsafe.Sizeof(NodeValue{})),
		MaxEntries: uint32(MaxEntries),
		Flags:      unix.BPF_F_NO_PREALLOC,
		Pinning:    ebpf.PinByName,
	})}
}

func (m *Map) Update(ip net.IP, nodeID uint16) error {
	key := newNodeKey(ip)
	val := NodeValue{NodeID: nodeID}
	return m.Map.Update(key, val, 0)
}

func (m *Map) Delete(ip net.IP) error {
	key := newNodeKey(ip)
	return m.Map.Delete(key)
}

// NodeIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of a node map.
type NodeIterateCallback func(*NodeKey, *NodeValue)

// IterateWithCallback iterates through all the keys/values of a node map,
// passing each key/value pair to the cb callback.
func (m Map) IterateWithCallback(cb NodeIterateCallback) error {
	return m.Map.IterateWithCallback(&NodeKey{}, &NodeValue{},
		func(k, v interface{}) {
			key := k.(*NodeKey)
			value := v.(*NodeValue)

			cb(key, value)
		})
}
