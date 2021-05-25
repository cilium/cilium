// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tunnel

import (
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"

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
		&TunnelEndpoint{},
		int(unsafe.Sizeof(TunnelEndpoint{})),
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
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type TunnelEndpoint struct {
	bpf.EndpointKey
}

func newTunnelEndpoint(ip net.IP) *TunnelEndpoint {
	return &TunnelEndpoint{
		EndpointKey: bpf.NewEndpointKey(ip),
	}
}

func (v TunnelEndpoint) NewValue() bpf.MapValue { return &TunnelEndpoint{} }

// SetTunnelEndpoint adds/replaces a prefix => tunnel-endpoint mapping
func (m *Map) SetTunnelEndpoint(encryptKey uint8, prefix, endpoint net.IP) error {
	key, val := newTunnelEndpoint(prefix), newTunnelEndpoint(endpoint)
	val.EndpointKey.Key = encryptKey
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

	return val.(*TunnelEndpoint).ToIP(), nil
}

// DeleteTunnelEndpoint removes a prefix => tunnel-endpoint mapping
func (m *Map) DeleteTunnelEndpoint(prefix net.IP) error {
	log.WithField(fieldPrefix, prefix).Debug("Deleting tunnel map entry")
	return TunnelMap.Delete(newTunnelEndpoint(prefix))
}
