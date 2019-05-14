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
	"sync"
	"unsafe"

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"golang.org/x/sys/unix"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-ipcache")

const (
	// MaxEntries is the maximum number of keys that can be present in the
	// RemoteEndpointMap.
	MaxEntries = 512000

	// Name is the canonical name for the IPCache map on the filesystem.
	Name = "cilium_ipcache"

	// maxPrefixLengths is an approximation of how many different CIDR
	// prefix lengths may be supported by the BPF datapath without causing
	// BPF code generation to exceed the verifier instruction limit.
	// It applies to Linux versions that lack support for LPM, ie < v4.11.
	//
	// This is based upon the defines in bpf/lxc_config.h, which in turn
	// are derived by building the bpf/ directory and running the script
	// test/bpf/verifier-test.sh, then adjusting the number of unique
	// prefix lengths until the script passes.
	maxPrefixLengths6 = 4
	maxPrefixLengths4 = 18
)

// Key implements the bpf.MapKey interface.
//
// Must be in sync with struct ipcache_key in <bpf/lib/maps.h>
type Key struct {
	Prefixlen uint32 `align:"lpm_key"`
	Pad1      uint16 `align:"pad1"`
	Pad2      uint8  `align:"pad2"`
	Family    uint8  `align:"family"`
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP types.IPv6 `align:"$union0"`
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
	SecurityIdentity uint32     `align:"sec_label"`
	TunnelEndpoint   types.IPv4 `align:"tunnel_endpoint"`
	Key              uint8      `align:"key"`
}

func (v *RemoteEndpointInfo) String() string {
	return fmt.Sprintf("%d %d %s", v.SecurityIdentity, v.Key, v.TunnelEndpoint)
}

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v *RemoteEndpointInfo) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// Map represents an IPCache BPF map.
type Map struct {
	bpf.Map

	// detectDeleteSupport is used to initialize 'supportsDelete' the first
	// time that a delete is issued from the datapath.
	detectDeleteSupport sync.Once

	// deleteSupport is set to 'true' initially, then is updated to set
	// whether the underlying kernel supports delete operations on the map
	// the first time that supportsDelete() is called.
	deleteSupport bool
}

// NewMap instantiates a Map.
func NewMap(name string) *Map {
	return &Map{
		Map: *bpf.NewMap(
			name,
			bpf.BPF_MAP_TYPE_LPM_TRIE,
			int(unsafe.Sizeof(Key{})),
			int(unsafe.Sizeof(RemoteEndpointInfo{})),
			MaxEntries,
			bpf.BPF_F_NO_PREALLOC, 0,
			func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
				k, v := Key{}, RemoteEndpointInfo{}

				if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
					return nil, nil, err
				}
				return &k, &v, nil
			},
		).WithCache(),
		deleteSupport: true,
	}
}

// delete removes a key from the ipcache BPF map, and returns whether the
// kernel supports the delete operation (true) or not (false), and any error
// that may have occurred while attempting to delete the entry.
//
// If "overwrite" is true, then if delete is not supported the entry's value
// will be overwritten with zeroes to signify that it's an invalid entry.
func (m *Map) delete(k bpf.MapKey, overwrite bool) (bool, error) {
	// Older kernels do not support deletion of LPM map entries so zero out
	// the entry instead of attempting a deletion
	err, errno := m.DeleteWithErrno(k)
	if errno == unix.ENOSYS {
		if overwrite {
			return false, m.Update(k, &RemoteEndpointInfo{})
		}
		return false, nil
	}

	return true, err
}

// Delete removes a key from the ipcache BPF map
func (m *Map) Delete(k bpf.MapKey) error {
	_, err := m.delete(k, true)
	return err
}

// GetMaxPrefixLengths determines how many unique prefix lengths are supported
// simultaneously based on the underlying BPF map type in use.
func (m *Map) GetMaxPrefixLengths(ipv6 bool) (count int) {
	if IPCache.MapType == bpf.BPF_MAP_TYPE_LPM_TRIE {
		if ipv6 {
			return net.IPv6len*8 + 1
		} else {
			return net.IPv4len*8 + 1
		}
	}
	if ipv6 {
		return maxPrefixLengths6
	}
	return maxPrefixLengths4
}

func (m *Map) supportsDelete() bool {
	m.detectDeleteSupport.Do(func() {
		// Entry is invalid because IPCache needs a family specified.
		invalidEntry := &Key{}
		m.deleteSupport, _ = m.delete(invalidEntry, false)
		log.Debugf("Detected IPCache delete operation support: %t", m.deleteSupport)
		if !m.deleteSupport {
			log.Infof("Periodic IPCache map swap will occur due to lack of kernel support for LPM delete operation. Upgrade to Linux 4.15 or higher to avoid this.")
		}
	})
	return m.deleteSupport
}

// SupportsDelete determines whether the underlying kernel map type supports
// the delete operation.
func SupportsDelete() bool {
	return IPCache.supportsDelete()
}

// BackedByLPM returns true if the IPCache is backed by a proper LPM
// implementation (provided by Linux kernels 4.11 or later), false otherwise.
func BackedByLPM() bool {
	return IPCache.MapType == bpf.BPF_MAP_TYPE_LPM_TRIE
}

var (
	// IPCache is a mapping of all endpoint IPs in the cluster which this
	// Cilium agent is a part of to their corresponding security identities.
	// It is a singleton; there is only one such map per agent.
	IPCache = NewMap(Name)
)

// Reopen attempts to close and re-open the IPCache map at the standard path
// on the filesystem.
func Reopen() error {
	return IPCache.Map.Reopen()
}
