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

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
)

var log = logging.DefaultLogger

const (
	// MaxEntries is the maximum number of keys that can be present in the
	// RemoteEndpointMap.
	MaxEntries = 512000

	// maxPrefixLengths is an approximation of how many different CIDR
	// prefix lengths may be supported by the BPF datapath without causing
	// BPF code generation to exceed the verifier instruction limit.
	// It applies to Linux versions that lack support for LPM, ie < v4.11.
	//
	// This was manually determined by setting up an egress policy with a
	// CIDRSet containing an exception. Reserved 'world' (/0) and 'cluster'
	// (/8) will always be inserted, which is what the first parameter
	// denotes. The CIDR for the CIDRSet is the second parameter, and the
	// exception is the third parameter.
	maxPrefixLengths = 2 - 8 + 32
)

// Key implements the bpf.MapKey interface.
//
// Must be in sync with struct bpf_ipcache_key in <bpf/lib/eps.h>
type Key struct {
	Prefixlen uint32
	Pad1      uint16
	Pad2      uint8
	Family    uint8
	IP        types.IPv6 // represents both IPv6 and IPv4 (in the lowest four bytes)
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k Key) NewValue() bpf.MapValue { return &RemoteEndpointInfo{} }

func getStaticPrefixBits() uint32 {
	staticMatchSize := unsafe.Sizeof(Key{})
	staticMatchSize -= unsafe.Sizeof(Key{}.Prefixlen)
	staticMatchSize -= unsafe.Sizeof(Key{}.IP)
	return uint32(staticMatchSize) * 8
}

func (k Key) String() string {
	prefixLen := k.Prefixlen - getStaticPrefixBits()
	switch k.Family {
	case bpf.EndpointKeyIPv4:
		ipStr := net.IP(k.IP[:net.IPv4len]).String()
		return fmt.Sprintf("%s/%d", ipStr, prefixLen)
	case bpf.EndpointKeyIPv6:
		ipStr := k.IP.String()
		return fmt.Sprintf("%s/%d", ipStr, prefixLen)
	}
	return fmt.Sprintf("<unknown>")
}

// getPrefixLen determines the length that should be set inside the Key so that
// the lookup prefix is correct in the BPF map key. The specified 'prefixBits'
// indicates the number of bits in the IP that must match to match the entry in
// the BPF ipcache.
func getPrefixLen(prefixBits int) uint32 {
	return getStaticPrefixBits() + uint32(prefixBits)
}

// NewKey returns an Key based on the provided IP address and mask. The address
// family is automatically detected
func NewKey(ip net.IP, mask net.IPMask) Key {
	result := Key{}

	ones, _ := mask.Size()
	if ip4 := ip.To4(); ip4 != nil {
		if mask == nil {
			ones = net.IPv4len * 8
		}
		result.Prefixlen = getPrefixLen(ones)
		result.Family = bpf.EndpointKeyIPv4
		copy(result.IP[:], ip4)
	} else {
		if mask == nil {
			ones = net.IPv6len * 8
		}
		result.Prefixlen = getPrefixLen(ones)
		result.Family = bpf.EndpointKeyIPv6
		copy(result.IP[:], ip)
	}

	return result
}

// RemoteEndpointInfo implements the bpf.MapValue interface. It contains the
// security identity of a remote endpoint.
type RemoteEndpointInfo struct {
	SecurityIdentity uint16
	Pad              [3]uint16
}

func (v *RemoteEndpointInfo) String() string {
	return fmt.Sprintf("%d", v.SecurityIdentity)
}

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v *RemoteEndpointInfo) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// Map represents an IPCache BPF map.
type Map struct {
	bpf.Map
}

// NewMap instantiates a Map.
func NewMap() *Map {
	return &Map{
		Map: *bpf.NewMap(
			"cilium_ipcache",
			bpf.BPF_MAP_TYPE_LPM_TRIE,
			int(unsafe.Sizeof(Key{})),
			int(unsafe.Sizeof(RemoteEndpointInfo{})),
			MaxEntries,
			bpf.BPF_F_NO_PREALLOC,
			func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
				k, v := Key{}, RemoteEndpointInfo{}

				if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
					return nil, nil, err
				}
				return &k, &v, nil
			},
		),
	}
}

// GetMaxPrefixLengths determines how many unique prefix lengths are supported
// simultaneously based on the underlying BPF map type in use.
func (m *Map) GetMaxPrefixLengths() (count int) {
	if IPCache.MapType == bpf.BPF_MAP_TYPE_LPM_TRIE {
		return net.IPv6len * 8
	}
	return maxPrefixLengths
}

var (
	// IPCache is a mapping of all endpoint IPs in the cluster which this
	// Cilium agent is a part of to their corresponding security identities.
	// It is a singleton; there is only one such map per agent.
	IPCache = NewMap()
)

func init() {
	err := bpf.OpenAfterMount(&IPCache.Map)
	if err != nil {
		log.WithError(err).Error("unable to open map")
	}
}
