// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// MaxEntries is the maximum number of keys that can be present in the
	// RemoteEndpointMap.
	MaxEntries = 512000

	// Name is the canonical name for the IPCache map on the filesystem.
	Name = "cilium_ipcache"
)

// Key implements the bpf.MapKey interface.
//
// Must be in sync with struct ipcache_key in <bpf/lib/maps.h>
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Key struct {
	Prefixlen uint32 `align:"lpm_key"`
	Pad1      uint16 `align:"pad1"`
	ClusterID uint8  `align:"cluster_id"`
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
	var (
		addr netip.Addr
		ok   bool
	)

	switch k.Family {
	case bpf.EndpointKeyIPv4:
		addr, ok = netip.AddrFromSlice(k.IP[:net.IPv4len])
		if !ok {
			return "<unknown>"
		}
	case bpf.EndpointKeyIPv6:
		addr = netip.AddrFrom16(k.IP)
	default:
		return "<unknown>"
	}

	prefixLen := int(k.Prefixlen - getStaticPrefixBits())
	clusterID := uint32(k.ClusterID)

	return cmtypes.PrefixClusterFrom(addr, prefixLen, clusterID).String()
}

func (k Key) IPNet() *net.IPNet {
	cidr := &net.IPNet{}
	prefixLen := k.Prefixlen - getStaticPrefixBits()
	switch k.Family {
	case bpf.EndpointKeyIPv4:
		cidr.IP = net.IP(k.IP[:net.IPv4len])
		cidr.Mask = net.CIDRMask(int(prefixLen), 32)
	case bpf.EndpointKeyIPv6:
		cidr.IP = net.IP(k.IP[:net.IPv6len])
		cidr.Mask = net.CIDRMask(int(prefixLen), 128)
	}
	return cidr
}

func (k Key) Prefix() netip.Prefix {
	var addr netip.Addr
	prefixLen := int(k.Prefixlen - getStaticPrefixBits())
	switch k.Family {
	case bpf.EndpointKeyIPv4:
		addr = netip.AddrFrom4(*(*[4]byte)(k.IP[:4]))
	case bpf.EndpointKeyIPv6:
		addr = netip.AddrFrom16(k.IP)
	}
	return netip.PrefixFrom(addr, prefixLen)
}

// getPrefixLen determines the length that should be set inside the Key so that
// the lookup prefix is correct in the BPF map key. The specified 'prefixBits'
// indicates the number of bits in the IP that must match to match the entry in
// the BPF ipcache.
func getPrefixLen(prefixBits int) uint32 {
	return getStaticPrefixBits() + uint32(prefixBits)
}

// NewKey returns an Key based on the provided IP address, mask, and ClusterID.
// The address family is automatically detected
func NewKey(ip net.IP, mask net.IPMask, clusterID uint8) Key {
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

	result.ClusterID = clusterID

	return result
}

// RemoteEndpointInfo implements the bpf.MapValue interface. It contains the
// security identity of a remote endpoint.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type RemoteEndpointInfo struct {
	SecurityIdentity uint32     `align:"sec_identity"`
	TunnelEndpoint   types.IPv4 `align:"tunnel_endpoint"`
	NodeID           uint16     `align:"node_id"`
	Key              uint8      `align:"key"`
}

func (v *RemoteEndpointInfo) String() string {
	return fmt.Sprintf("identity=%d encryptkey=%d tunnelendpoint=%s nodeid=%d",
		v.SecurityIdentity, v.Key, v.TunnelEndpoint, v.NodeID)
}

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v *RemoteEndpointInfo) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// Map represents an IPCache BPF map.
type Map struct {
	bpf.Map
}

func newIPCacheMap(name string) *bpf.Map {
	return bpf.NewMap(
		name,
		bpf.MapTypeLPMTrie,
		&Key{},
		int(unsafe.Sizeof(Key{})),
		&RemoteEndpointInfo{},
		int(unsafe.Sizeof(RemoteEndpointInfo{})),
		MaxEntries,
		bpf.BPF_F_NO_PREALLOC,
		bpf.ConvertKeyValue)
}

// NewMap instantiates a Map.
func NewMap(name string) *Map {
	return &Map{
		Map: *newIPCacheMap(name).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(name)),
	}
}

// GetMaxPrefixLengths determines how many unique prefix lengths are supported
// simultaneously based on the underlying BPF map type in use.
func (m *Map) GetMaxPrefixLengths() (ipv6, ipv4 int) {
	return net.IPv6len*8 + 1, net.IPv4len*8 + 1
}

var (
	// IPCache is a mapping of all endpoint IPs in the cluster which this
	// Cilium agent is a part of to their corresponding security identities.
	// It is a singleton; there is only one such map per agent.
	ipcache *Map
	once    = &sync.Once{}
)

// IPCacheMap gets the ipcache Map singleton. If it has not already been done,
// this also initializes the Map.
func IPCacheMap() *Map {
	once.Do(func() {
		ipcache = NewMap(Name)
	})
	return ipcache
}
