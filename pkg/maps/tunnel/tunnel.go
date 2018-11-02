// Copyright 2016-2018 Authors of Cilium
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
	"os"
	"path/filepath"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/defaults"

	"github.com/sirupsen/logrus"
)

const (
	MapName = "cilium_tunnel_map"

	// Cilium versions < 1.0 used this tunnel map name, we remove it when
	// we open the new tunnel map. In a future release, we should remove
	// this downgrade handling code
	oldMapName = "tunnel_endpoint_map"

	// MaxEntries is the maximum entries in the tunnel endpoint map
	MaxEntries = 65536
)

var (
	// TunnelMap represents the BPF map for tunnels
	TunnelMap = &Map{Map: bpf.NewMap(MapName,
		bpf.MapTypeHash,
		int(unsafe.Sizeof(tunnelEndpoint{})),
		int(unsafe.Sizeof(tunnelEndpoint{})),
		MaxEntries,
		0, 0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			k, v := tunnelEndpoint{}, tunnelEndpoint{}

			if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
				return nil, nil, err
			}

			return &k, &v, nil
		}).WithCache(),
	}
)

// Map implements tunnel connectivity configuration in the BPF datapath.
type Map struct {
	*bpf.Map
}

func init() {
	TunnelMap.NonPersistent = true
	bpf.OpenAfterMount(TunnelMap.Map)

	// Remove old map and ignore errors; this is the "normal" case.
	// BPFFS map root in older versions of Cilium wasn't dynamic, so the
	// path of this old map will be always
	// /sys/fs/bpf/tc/globals/tunnel_endpoint_map
	os.Remove(filepath.Join(defaults.DefaultMapRoot, defaults.DefaultMapPrefix, oldMapName))
}

type tunnelEndpoint struct {
	bpf.EndpointKey
}

func newTunnelEndpoint(ip net.IP) *tunnelEndpoint {
	return &tunnelEndpoint{
		EndpointKey: bpf.NewEndpointKey(ip),
	}
}

func (v tunnelEndpoint) NewValue() bpf.MapValue { return &tunnelEndpoint{} }

// SetTunnelEndpoint adds/replaces a prefix => tunnel-endpoint mapping
func (m *Map) SetTunnelEndpoint(prefix net.IP, endpoint net.IP) error {
	key, val := newTunnelEndpoint(prefix), newTunnelEndpoint(endpoint)

	log.WithFields(logrus.Fields{
		fieldPrefix:   prefix,
		fieldEndpoint: endpoint,
	}).Debug("Updating tunnel map entry")

	return TunnelMap.Update(key, val)
}

// DeleteTunnelEndpoint removes a prefix => tunnel-endpoint mapping
func (m *Map) DeleteTunnelEndpoint(prefix net.IP) error {
	log.WithField(fieldPrefix, prefix).Debug("Deleting tunnel map entry")
	return TunnelMap.Delete(newTunnelEndpoint(prefix))
}
