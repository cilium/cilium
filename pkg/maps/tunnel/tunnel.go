// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tunnel

import (
	"fmt"
	"net"
	"sync"

	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MapName = "cilium_tunnel_map"

	// MaxEntries is the maximum entries in the tunnel endpoint map
	MaxEntries = 65536
)

var (
	// TunnelMap represents the BPF map for tunnels
	tunnelMap     *Map
	tunnelMapInit = &sync.Once{}
)

func TunnelMap() *Map {
	tunnelMapInit.Do(func() {
		if tunnelMap == nil {
			tunnelMap = NewTunnelMap(MapName)
		}
	})
	return tunnelMap
}

// Map implements tunnel connectivity configuration in the BPF datapath.
type Map struct {
	*bpf.Map
}

// NewTunnelMap returns a new tunnel map.
func NewTunnelMap(mapName string) *Map {
	return &Map{Map: bpf.NewMap(
		mapName,
		ebpf.Hash,
		&TunnelKey{},
		&TunnelValue{},
		MaxEntries,
		0,
	)}
}

type TunnelIP struct {
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP     types.IPv6 `align:"$union0"`
	Family uint8      `align:"family"`
}

type TunnelKey struct {
	TunnelIP
	Pad       uint8  `align:"pad"`
	ClusterID uint16 `align:"cluster_id"`
}

// String provides a string representation of the TunnelKey.
func (k TunnelKey) String() string {
	if ip := k.toIP(); ip != nil {
		addrCluster := cmtypes.AddrClusterFrom(
			netipx.MustFromStdIP(ip),
			uint32(k.ClusterID),
		)
		return addrCluster.String()
	}
	return "nil"
}

func (k *TunnelKey) New() bpf.MapKey { return &TunnelKey{} }

type TunnelValue struct {
	TunnelIP
	Key uint8  `align:"key"`
	Pad uint16 `align:"pad"`
}

// String provides a string representation of the TunnelValue.
func (k TunnelValue) String() string {
	if ip := k.toIP(); ip != nil {
		return ip.String() + ":" + fmt.Sprintf("%d", k.Key)
	}
	return "nil"
}

func (k *TunnelValue) New() bpf.MapValue { return &TunnelValue{} }

// ToIP converts the TunnelIP into a net.IP structure.
func (v TunnelIP) toIP() net.IP {
	switch v.Family {
	case bpf.EndpointKeyIPv4:
		return v.IP[:4]
	case bpf.EndpointKeyIPv6:
		return v.IP[:]
	}
	return nil
}
