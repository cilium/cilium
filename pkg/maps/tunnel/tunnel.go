// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tunnel

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MapName = "cilium_tunnel_map"

	// MaxEntries is the maximum entries in the tunnel endpoint map
	MaxEntries = 65536
)

var (
	// TunnelMap represents the BPF map for tunnels
	TunnelMap = NewTunnelMap(MapName)
)

// Map implements tunnel connectivity configuration in the BPF datapath.
type Map struct {
	*bpf.Map
}

// NewTunnelMap returns a new tunnel map with the specified name.
func NewTunnelMap(name string) *Map {
	return &Map{Map: bpf.NewMap(MapName,
		bpf.MapTypeHash,
		&TunnelKey{},
		int(unsafe.Sizeof(TunnelKey{})),
		&TunnelValue{},
		int(unsafe.Sizeof(TunnelValue{})),
		MaxEntries,
		0, 0,
		bpf.ConvertKeyValue,
	).WithCache().WithPressureMetric().WithNonPersistent(),
	}
}

// +k8s:deepcopy-gen=true
type TunnelIP struct {
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP     types.IPv6 `align:"$union0"`
	Family uint8      `align:"family"`
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type TunnelKey struct {
	TunnelIP
	ClusterID uint8  `align:"cluster_id"`
	Pad       uint16 `align:"pad"`
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *TunnelKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// String provides a string representation of the TunnelKey.
func (k TunnelKey) String() string {
	if ip := k.toIP(); ip != nil {
		return ip.String()
	}
	return "nil"
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type TunnelValue struct {
	TunnelIP
	Key uint8  `align:"key"`
	Pad uint16 `align:"pad"`
}

// GetValuePtr returns the unsafe pointer to the BPF key for users that
// use TunnelValue as a value in bpf maps
func (k *TunnelValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(k) }

// String provides a string representation of the TunnelValue.
func (k TunnelValue) String() string {
	if ip := k.toIP(); ip != nil {
		return ip.String() + ":" + fmt.Sprintf("%d", k.Key)
	}
	return "nil"
}

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

func newTunnelKey(ip net.IP) *TunnelKey {
	result := TunnelKey{}
	result.TunnelIP = newTunnelIP(ip)
	return &result
}

func (v TunnelKey) NewValue() bpf.MapValue { return &TunnelValue{} }

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

func (v TunnelValue) NewValue() bpf.MapValue { return &TunnelValue{} }

// SetTunnelEndpoint adds/replaces a prefix => tunnel-endpoint mapping
func (m *Map) SetTunnelEndpoint(encryptKey uint8, prefix, endpoint net.IP) error {
	key := newTunnelKey(prefix)
	val := newTunnelValue(endpoint, encryptKey)

	log.WithFields(logrus.Fields{
		fieldPrefix:   prefix,
		fieldEndpoint: endpoint,
		fieldKey:      encryptKey,
	}).Debug("Updating tunnel map entry")

	return TunnelMap.Update(key, val)
}

// GetTunnelEndpoint removes a prefix => tunnel-endpoint mapping
func (m *Map) GetTunnelEndpoint(prefix net.IP) (net.IP, error) {
	val, err := TunnelMap.Lookup(newTunnelKey(prefix))
	if err != nil {
		return net.IP{}, err
	}

	return val.(*TunnelValue).toIP(), nil
}

// DeleteTunnelEndpoint removes a prefix => tunnel-endpoint mapping
func (m *Map) DeleteTunnelEndpoint(prefix net.IP) error {
	log.WithField(fieldPrefix, prefix).Debug("Deleting tunnel map entry")
	return TunnelMap.Delete(newTunnelKey(prefix))
}

// SilentDeleteTunnelEndpoint removes a prefix => tunnel-endpoint mapping.
// If the prefix is not found no error is returned.
func (m *Map) SilentDeleteTunnelEndpoint(prefix net.IP) error {
	log.WithField(fieldPrefix, prefix).Debug("Silently deleting tunnel map entry")
	_, err := TunnelMap.SilentDelete(newTunnelKey(prefix))
	return err
}
