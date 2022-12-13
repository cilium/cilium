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
	bpfTypes "github.com/cilium/cilium/pkg/bpf/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	ippkg "github.com/cilium/cilium/pkg/ip"
	tunnelTypes "github.com/cilium/cilium/pkg/maps/tunnel/types"
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
		&TunnelKey{},
		int(unsafe.Sizeof(TunnelKey{})),
		&TunnelValue{},
		int(unsafe.Sizeof(TunnelValue{})),
		MaxEntries,
		0, 0,
		bpf.ConvertKeyValue,
	).WithCache().WithPressureMetric().WithNonPersistent().
		WithEvents(option.Config.GetEventBufferConfig(MapName)),
	}
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf/types.MapKey
type TunnelKey tunnelTypes.TunnelKey

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *TunnelKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// String provides a string representation of the TunnelKey.
func (k TunnelKey) String() string {
	if ip := k.ToIP(); ip != nil {
		addrCluster := cmtypes.AddrClusterFrom(
			ippkg.MustAddrFromIP(ip),
			uint32(k.ClusterID),
		)
		return addrCluster.String()
	}
	return "nil"
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf/types.MapValue
type TunnelValue tunnelTypes.TunnelValue

// GetValuePtr returns the unsafe pointer to the BPF key for users that
// use TunnelValue as a value in bpf maps
func (k *TunnelValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(k) }

// String provides a string representation of the TunnelValue.
func (k TunnelValue) String() string {
	if ip := k.ToIP(); ip != nil {
		return ip.String() + ":" + fmt.Sprintf("%d %d", k.Key, k.NodeID)
	}
	return "nil"
}

func newTunnelKey(ip net.IP, clusterID uint32) (*TunnelKey, error) {
	if clusterID > cmtypes.ClusterIDMax {
		return nil, fmt.Errorf("ClusterID %d is too large. ClusterID > %d is not supported in TunnelMap", clusterID, cmtypes.ClusterIDMax)
	}

	result := TunnelKey{}
	result.TunnelIP = newTunnelIP(ip)
	result.ClusterID = uint8(clusterID)
	return &result, nil
}

func (v TunnelKey) NewValue() bpfTypes.MapValue { return &TunnelValue{} }

func newTunnelValue(ip net.IP, key uint8, nodeID uint16) *TunnelValue {
	result := TunnelValue{}
	result.TunnelIP = newTunnelIP(ip)
	result.Key = key
	result.NodeID = nodeID
	return &result
}

func newTunnelIP(ip net.IP) tunnelTypes.TunnelIP {
	result := tunnelTypes.TunnelIP{}
	if ip4 := ip.To4(); ip4 != nil {
		result.Family = bpfTypes.EndpointKeyIPv4
		copy(result.IP[:], ip4)
	} else {
		result.Family = bpfTypes.EndpointKeyIPv6
		copy(result.IP[:], ip)
	}
	return result
}

func (v TunnelValue) NewValue() bpfTypes.MapValue { return &TunnelValue{} }

// SetTunnelEndpoint adds/replaces a prefix => tunnel-endpoint mapping
func (m *Map) SetTunnelEndpoint(encryptKey uint8, nodeID uint16, prefix cmtypes.AddrCluster, endpoint net.IP) error {
	key, err := newTunnelKey(prefix.AsNetIP(), prefix.ClusterID())
	if err != nil {
		return err
	}

	val := newTunnelValue(endpoint, encryptKey, nodeID)

	log.WithFields(logrus.Fields{
		fieldPrefix:   prefix,
		fieldEndpoint: endpoint,
		fieldKey:      encryptKey,
		fieldNodeID:   nodeID,
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

	return val.(*TunnelValue).ToIP(), nil
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
