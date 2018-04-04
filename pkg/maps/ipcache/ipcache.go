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

package ipcache

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
)

var log = logging.DefaultLogger

const (
	// MaxEntries is the maximum number of keys that can be present in the
	// RemoteEndpointMap.
	MaxEntries = 512000
)

// EndpointKey implements the bpf.MapKey interface.
type EndpointKey struct {
	bpf.EndpointKey
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k EndpointKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(&k) }

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k EndpointKey) NewValue() bpf.MapValue { return &RemoteEndpointInfo{} }

// NewEndpointKey returns an EndpointKey based on the provided IP address. The
// address family is automatically detected
func NewEndpointKey(ip net.IP) EndpointKey {
	return EndpointKey{
		EndpointKey: bpf.NewEndpointKey(ip),
	}
}

// RemoteEndpointInfo implements the bpf.MapValue interface. It contains the
// security identity of a remote endpoint.
type RemoteEndpointInfo struct {
	SecurityIdentity uint16
	Pad              [3]uint16
}

func (v RemoteEndpointInfo) String() string {
	return fmt.Sprintf("%d", v.SecurityIdentity)
}

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v RemoteEndpointInfo) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(&v) }

var (
	// IPCache is a mapping of all endpoint IPs in the cluster which this
	// Cilium agent is a part of to their corresponding security identities.
	// It is a singleton; there is only one such map per agent.
	IPCache = bpf.NewMap(
		"cilium_ipcache",
		bpf.BPF_MAP_TYPE_HASH,
		int(unsafe.Sizeof(EndpointKey{})),
		int(unsafe.Sizeof(RemoteEndpointInfo{})),
		MaxEntries,
		0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			k, v := EndpointKey{}, RemoteEndpointInfo{}

			if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
				return nil, nil, err
			}
			return k, v, nil
		},
	)
)

func init() {
	err := bpf.OpenAfterMount(IPCache)
	if err != nil {
		log.WithError(err).Error("unable to open map")
	}
}
