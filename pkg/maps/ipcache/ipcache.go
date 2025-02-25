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
	"github.com/cilium/cilium/pkg/ebpf"
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
type Key struct {
	Prefixlen uint32 `align:"lpm_key"`
	ClusterID uint16 `align:"cluster_id"`
	Pad1      uint8  `align:"pad1"`
	Family    uint8  `align:"family"`
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP types.IPv6 `align:"$union0"`
}

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

	return cmtypes.PrefixClusterFrom(addr, prefixLen, cmtypes.WithClusterID(clusterID)).String()
}

func (k *Key) New() bpf.MapKey { return &Key{} }

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
func NewKey(ip net.IP, mask net.IPMask, clusterID uint16) Key {
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

// RemoteEndpointInfoFlags represents various flags that can be attached to
// remote endpoints in the IPCache.
type RemoteEndpointInfoFlags uint8

// String returns a human-readable representation of the flags present in the
// RemoteEndpointInfoFlags.
// The output format is the string name of each flag contained in the flag set,
// separated by a comma. If no flags are set, then "<none>" is returned.
func (f RemoteEndpointInfoFlags) String() string {
	// If more flags are added in the future, then this method will need
	// a re-work to support multiple flags.
	// Right now, it only supports checking for FlagSkipTunnel.
	if f&FlagSkipTunnel == FlagSkipTunnel {
		return "skiptunnel"
	}

	return "<none>"
}

const (
	// FlagSkipTunnel can be applied to a remote endpoint to signal that
	// packets destined for said endpoint shall not be forwarded through
	// a VXLAN/Geneve tunnel, regardless of Cilium's configuration.
	FlagSkipTunnel RemoteEndpointInfoFlags = 1 << iota
)

// RemoteEndpointInfo implements the bpf.MapValue interface. It contains the
// security identity of a remote endpoint.
type RemoteEndpointInfo struct {
	SecurityIdentity uint32 `align:"sec_identity"`
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	TunnelEndpoint types.IPv6 `align:"tunnel_endpoint"`
	_              uint16
	Key            uint8                   `align:"key"`
	Flags          RemoteEndpointInfoFlags `align:"flag_skip_tunnel"`
}

func (v *RemoteEndpointInfo) String() string {
	return fmt.Sprintf("identity=%d encryptkey=%d tunnelendpoint=%s flags=%s",
		v.SecurityIdentity, v.Key, v.TunnelEndpoint, v.Flags)
}

func (v *RemoteEndpointInfo) New() bpf.MapValue { return &RemoteEndpointInfo{} }

// NewValue returns a RemoteEndpointInfo based on the provided security
// identity, tunnel endpoint IP, IPsec key, and flags. The address family is
// automatically detected.
func NewValue(secID uint32, tunnelEndpoint net.IP, key uint8, flags RemoteEndpointInfoFlags) RemoteEndpointInfo {
	result := RemoteEndpointInfo{}

	result.SecurityIdentity = secID
	if ip4 := tunnelEndpoint.To4(); ip4 != nil {
		copy(result.TunnelEndpoint[:], ip4)
	} else {
		copy(result.TunnelEndpoint[:], tunnelEndpoint)
	}
	result.Key = key
	result.Flags = flags

	return result
}

// Map represents an IPCache BPF map.
type Map struct {
	bpf.Map
}

func newIPCacheMap(name string) *bpf.Map {
	return bpf.NewMap(
		name,
		ebpf.LPMTrie,
		&Key{},
		&RemoteEndpointInfo{},
		MaxEntries,
		bpf.BPF_F_NO_PREALLOC)
}

// NewMap instantiates a Map.
func NewMap(name string) *Map {
	return &Map{
		Map: *newIPCacheMap(name).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(name)),
	}
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
