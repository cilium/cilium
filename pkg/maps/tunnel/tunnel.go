// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2019 Authors of Cilium

package tunnel

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/types"

	"github.com/sirupsen/logrus"
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
		&TunnelEndpoint{},
		int(unsafe.Sizeof(TunnelEndpoint{})),
		&TunnelEndpointInfo{},
		int(unsafe.Sizeof(TunnelEndpointInfo{})),
		MaxEntries,
		0, 0,
		bpf.ConvertKeyValue,
	).WithCache().WithPressureMetric(),
	}
}

func init() {
	TunnelMap.NonPersistent = true
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type TunnelEndpoint struct {
	bpf.EndpointKey
}

// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type TunnelEndpointInfo struct {
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP     types.IPv6 `align:"$union0"`
	Family uint8      `align:"family"`
	Key    uint8      `align:"key"`
	Pad2   uint16     `align:"pad5"`
}

// String returns the human readable representation of an TunnelEndpointInfo
func (v TunnelEndpointInfo) String() string {
	if ip := v.ToIP(); ip != nil {
		return fmt.Sprintf("ip=%s family=%-3d key=%-3d",
			ip,
			v.Family,
			v.Key,
		)
	}
	return "nil"
}

// GetValuePtr returns the unsafe pointer to the BPF value
func (v *TunnelEndpointInfo) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

func newTunnelEndpoint(ip net.IP) *TunnelEndpoint {
	return &TunnelEndpoint{
		EndpointKey: bpf.NewEndpointKey(ip),
	}
}

func (k TunnelEndpoint) NewValue() bpf.MapValue { return &TunnelEndpointInfo{} }

func newTunnelEndpointInfo(ip net.IP) *TunnelEndpointInfo {
	result := TunnelEndpointInfo{}

	if ip4 := ip.To4(); ip4 != nil {
		result.Family = bpf.EndpointKeyIPv4
		copy(result.IP[:], ip4)
	} else {
		result.Family = bpf.EndpointKeyIPv6
		copy(result.IP[:], ip)
	}

	return &result
}

// ToIP converts the TunnelEndpointInfo IP field into a net.IP structure.
func (v TunnelEndpointInfo) ToIP() net.IP {
	switch v.Family {
	case bpf.EndpointKeyIPv4:
		return v.IP[:4]
	case bpf.EndpointKeyIPv6:
		return v.IP[:]
	}
	return nil
}

// SetTunnelEndpoint adds/replaces a prefix => tunnel-endpoint mapping
func (m *Map) SetTunnelEndpoint(encryptKey uint8, prefix, endpoint net.IP) error {
	key, val := newTunnelEndpoint(prefix), newTunnelEndpointInfo(endpoint)
	val.Key = encryptKey
	log.WithFields(logrus.Fields{
		fieldPrefix:   prefix,
		fieldEndpoint: endpoint,
		fieldKey:      encryptKey,
	}).Debug("Updating tunnel map entry")

	return TunnelMap.Update(key, val)
}

// GetTunnelEndpoint removes a prefix => tunnel-endpoint mapping
func (m *Map) GetTunnelEndpoint(prefix net.IP) (net.IP, error) {
	val, err := TunnelMap.Lookup(newTunnelEndpoint(prefix))
	if err != nil {
		return net.IP{}, err
	}

	return val.(*TunnelEndpointInfo).ToIP(), nil
}

// DeleteTunnelEndpoint removes a prefix => tunnel-endpoint mapping
func (m *Map) DeleteTunnelEndpoint(prefix net.IP) error {
	log.WithField(fieldPrefix, prefix).Debug("Deleting tunnel map entry")
	return TunnelMap.Delete(newTunnelEndpoint(prefix))
}
