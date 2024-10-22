// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tunnel

import (
	"fmt"
	"net"
	"sync"

	"github.com/sirupsen/logrus"
	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/option"
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

// SetTunnelMap sets the tunnel map. Only used for testing.
func SetTunnelMap(m *Map) {
	if tunnelMap != nil {
		tunnelMap.UnpinIfExists()
	}

	tunnelMap = m
}

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
	).WithCache().WithPressureMetric().
		WithEvents(option.Config.GetEventBufferConfig(MapName)),
	}
}

// +k8s:deepcopy-gen=true
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

func newTunnelKey(ip net.IP, clusterID uint32) (*TunnelKey, error) {
	if clusterID > cmtypes.ClusterIDMax {
		return nil, fmt.Errorf("ClusterID %d is too large. ClusterID > %d is not supported in TunnelMap", clusterID, cmtypes.ClusterIDMax)
	}

	result := TunnelKey{}
	result.TunnelIP = newTunnelIP(ip)
	result.ClusterID = uint16(clusterID)
	return &result, nil
}

func newTunnelValue(ip net.IP, key uint8) *TunnelValue {
	result := TunnelValue{}
	result.TunnelIP = newTunnelIP(ip)
	result.Key = key
	return &result
}

func newTunnelIP(ip net.IP) TunnelIP {
	result := TunnelIP{}
	if ip4 := ip.To4(); ip4 != nil {
		result.Family = bpf.EndpointKeyIPv4
		copy(result.IP[:], ip4)
	} else {
		result.Family = bpf.EndpointKeyIPv6
		copy(result.IP[:], ip)
	}
	return result
}

// SetTunnelEndpoint adds/replaces a prefix => tunnel-endpoint mapping
func (m *Map) SetTunnelEndpoint(encryptKey uint8, prefix cmtypes.AddrCluster, endpoint net.IP) error {
	key, err := newTunnelKey(prefix.AsNetIP(), prefix.ClusterID())
	if err != nil {
		return err
	}

	val := newTunnelValue(endpoint, encryptKey)

	log.WithFields(logrus.Fields{
		fieldPrefix:   prefix,
		fieldEndpoint: endpoint,
		fieldKey:      encryptKey,
	}).Debug("Updating tunnel map entry")

	return m.Update(key, val)
}

// GetTunnelEndpoint retrieves a prefix => tunnel-endpoint mapping
func (m *Map) GetTunnelEndpoint(prefix cmtypes.AddrCluster) (net.IP, error) {
	key, err := newTunnelKey(prefix.AsNetIP(), prefix.ClusterID())
	if err != nil {
		return net.IP{}, err
	}

	val, err := m.Lookup(key)
	if err != nil {
		return net.IP{}, err
	}

	return val.(*TunnelValue).toIP(), nil
}

// DeleteTunnelEndpoint removes a prefix => tunnel-endpoint mapping
func (m *Map) DeleteTunnelEndpoint(prefix cmtypes.AddrCluster) error {
	key, err := newTunnelKey(prefix.AsNetIP(), prefix.ClusterID())
	if err != nil {
		return err
	}
	log.WithField(fieldPrefix, prefix).Debug("Deleting tunnel map entry")
	return m.Delete(key)
}

// SilentDeleteTunnelEndpoint removes a prefix => tunnel-endpoint mapping.
// If the prefix is not found no error is returned.
func (m *Map) SilentDeleteTunnelEndpoint(prefix cmtypes.AddrCluster) error {
	key, err := newTunnelKey(prefix.AsNetIP(), prefix.ClusterID())
	if err != nil {
		return err
	}
	log.WithField(fieldPrefix, prefix).Debug("Silently deleting tunnel map entry")
	_, err = m.SilentDelete(key)
	return err
}
