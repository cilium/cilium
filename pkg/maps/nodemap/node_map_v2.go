// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"fmt"
	"log/slog"
	"net/netip"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/maps"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/types"
)

// compile time check of MapV2 interface
var _ MapV2 = (*nodeMapV2)(nil)

const (
	MapNameV2         = maps.CiliumNodeMapV2
	DefaultMaxEntries = 16384
)

// MapV2 provides access to the eBPF map node.
type MapV2 interface {
	// Update inserts or updates the node map object associated with the provided
	// IP, node id, and SPI.
	Update(ip netip.Addr, nodeID uint16, SPI uint8, internalIP bool) error

	// Delete deletes the node map object associated with the provided
	// IP.
	Delete(ip netip.Addr) error

	// IterateWithCallback iterates through all the keys/values of a node map,
	// passing each key/value pair to the cb callback.
	IterateWithCallback(cb NodeIterateCallbackV2) error
}

// nodeMapV2 is an iteration on nodeMap which associates an IPSec SPI with each
// node in the map.
type nodeMapV2 struct {
	bpfMap *bpf.Map
}

func newMapV2(mapName string, conf Config) *nodeMapV2 {
	flags := uint32(unix.BPF_F_NO_PREALLOC | unix.BPF_F_RDONLY_PROG)
	m := bpf.NewMap(mapName, ebpf.Hash, &NodeKey{}, &NodeValueV2{}, int(conf.NodeMapMax), flags)
	return &nodeMapV2{bpfMap: m}
}

type NodeKey struct {
	Pad1   uint16 `align:"pad1"`
	Pad2   uint8  `align:"pad2"`
	Family uint8  `align:"family"`
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP types.IPv6 `align:"$union0"`
}

func (k *NodeKey) New() bpf.MapKey { return &NodeKey{} }

func (k *NodeKey) String() string {
	switch k.Family {
	case bpf.EndpointKeyIPv4:
		return netip.AddrFrom4([4]byte(k.IP[:4])).String()
	case bpf.EndpointKeyIPv6:
		return k.IP.String()
	}
	return "<unknown>"
}

func newNodeKey(ip netip.Addr) NodeKey {
	result := NodeKey{}
	if !ip.IsValid() {
		return result
	}
	if ip.Is4() {
		ip4 := ip.As4()
		result.Family = bpf.EndpointKeyIPv4
		copy(result.IP[:], ip4[:])
	} else {
		ip6 := ip.As16()
		result.Family = bpf.EndpointKeyIPv6
		copy(result.IP[:], ip6[:])
	}
	return result
}

type NodeValueV2 struct {
	NodeID     uint16
	SPI        uint8
	InternalIP uint8
}

func (n *NodeValueV2) New() bpf.MapValue { return &NodeValueV2{} }

func (n *NodeValueV2) String() string {
	return fmt.Sprintf("id=%d spi=%d internalip=%d", n.NodeID, n.SPI, n.InternalIP)
}

func (m *nodeMapV2) Update(ip netip.Addr, nodeID uint16, SPI uint8, internalIP bool) error {
	key := newNodeKey(ip)
	val := NodeValueV2{NodeID: nodeID, SPI: SPI}
	if internalIP {
		val.InternalIP = 1
	}
	if err := m.bpfMap.Update(&key, &val); err != nil {
		return fmt.Errorf("failed to update node map: %w", err)
	}

	return nil
}

func (m *nodeMapV2) Delete(ip netip.Addr) error {
	key := newNodeKey(ip)
	if err := m.bpfMap.Delete(&key); err != nil {
		return fmt.Errorf("failed to delete node map: %w", err)
	}

	return nil
}

// NodeIterateCallbackV2 represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of a node map.
type NodeIterateCallbackV2 func(*NodeKey, *NodeValueV2)

func (m *nodeMapV2) IterateWithCallback(cb NodeIterateCallbackV2) error {
	return m.bpfMap.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*NodeKey)
		value := v.(*NodeValueV2)
		cb(key, value)
	})
}

// LoadNodeMapV2 loads the pre-initialized node map for access.
// This should only be used from components which aren't capable of using hive - mainly the Cilium CLI.
// It needs to initialized beforehand via the Cilium Agent.
func LoadNodeMapV2(logger *slog.Logger) (MapV2, error) {
	bpfMap, err := bpf.OpenMap(bpf.MapPath(logger, MapNameV2), &NodeKey{}, &NodeValueV2{})
	if err != nil {
		return nil, fmt.Errorf("failed to load %s bpf map: %w", MapNameV2, err)
	}

	return &nodeMapV2{bpfMap: bpfMap}, nil
}
