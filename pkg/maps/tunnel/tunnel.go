// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tunnel

import (
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/option"
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
	tunnelMap = m
}

func TunnelMap() *Map {
	tunnelMapInit.Do(func() {
		tunnelMap = NewTunnelMap(MapName)
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
		bpf.MapTypeHash,
		&TunnelEndpoint{},
		int(unsafe.Sizeof(TunnelEndpoint{})),
		&TunnelEndpoint{},
		int(unsafe.Sizeof(TunnelEndpoint{})),
		MaxEntries,
		0, 0,
		bpf.ConvertKeyValue,
	).WithCache().WithPressureMetric().WithNonPersistent().
		WithEvents(option.Config.GetEventBufferConfig(MapName)),
	}
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type TunnelEndpoint struct {
	bpf.EndpointKey
}

func newTunnelEndpoint(ip net.IP, clusterID uint32) (*TunnelEndpoint, error) {
	if clusterID > cmtypes.ClusterIDMax {
		return nil, fmt.Errorf("ClusterID %d is too large. ClusterID > %d is not supported in TunnelMap", clusterID, cmtypes.ClusterIDMax)
	}
	return &TunnelEndpoint{
		EndpointKey: bpf.NewEndpointKey(ip, uint8(clusterID)),
	}, nil
}

func (v TunnelEndpoint) NewValue() bpf.MapValue { return &TunnelEndpoint{} }

// SetTunnelEndpoint adds/replaces a prefix => tunnel-endpoint mapping
func (m *Map) SetTunnelEndpoint(encryptKey uint8, prefix cmtypes.AddrCluster, endpoint net.IP) error {
	key, err := newTunnelEndpoint(prefix.AsNetIP(), prefix.ClusterID())
	if err != nil {
		return err
	}

	val, err := newTunnelEndpoint(endpoint, 0)
	if err != nil {
		return err
	}

	val.EndpointKey.Key = encryptKey
	log.WithFields(logrus.Fields{
		fieldPrefix:   prefix,
		fieldEndpoint: endpoint,
		fieldKey:      encryptKey,
	}).Debug("Updating tunnel map entry")

	return m.Update(key, val)
}

// GetTunnelEndpoint removes a prefix => tunnel-endpoint mapping
func (m *Map) GetTunnelEndpoint(prefix cmtypes.AddrCluster) (net.IP, error) {
	key, err := newTunnelEndpoint(prefix.AsNetIP(), prefix.ClusterID())
	if err != nil {
		return net.IP{}, err
	}

	val, err := m.Lookup(key)
	if err != nil {
		return net.IP{}, err
	}

	return val.(*TunnelEndpoint).ToIP(), nil
}

// DeleteTunnelEndpoint removes a prefix => tunnel-endpoint mapping
func (m *Map) DeleteTunnelEndpoint(prefix cmtypes.AddrCluster) error {
	key, err := newTunnelEndpoint(prefix.AsNetIP(), prefix.ClusterID())
	if err != nil {
		return err
	}
	log.WithField(fieldPrefix, prefix).Debug("Deleting tunnel map entry")
	return m.Delete(key)
}

// SilentDeleteTunnelEndpoint removes a prefix => tunnel-endpoint mapping.
// If the prefix is not found no error is returned.
func (m *Map) SilentDeleteTunnelEndpoint(prefix cmtypes.AddrCluster) error {
	key, err := newTunnelEndpoint(prefix.AsNetIP(), prefix.ClusterID())
	if err != nil {
		return err
	}
	log.WithField(fieldPrefix, prefix).Debug("Silently deleting tunnel map entry")
	_, err = m.SilentDelete(key)
	return err
}
