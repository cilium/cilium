// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"unsafe"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// MaxEntries is the maximum number of keys that can be present in the
	// RemoteEndpointMap.
	MaxEntries = 512000

	// OldName is the canonical name for the v1 IPCache map on the filesystem.
	OldName = "cilium_ipcache"

	// Name is the canonical name for the IPCache map on the filesystem.
	Name = "cilium_ipcache_v2"
)

// Key implements the bpf.MapKey interface.
//
// Must be in sync with struct ipcache_key in bpf/...
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

	return cmtypes.PrefixClusterFrom(netip.PrefixFrom(addr, prefixLen), cmtypes.WithClusterID(clusterID)).String()
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
	flags := ""
	if f&FlagSkipTunnel != 0 {
		flags += "skiptunnel,"
	}
	if f&FlagHasTunnelEndpoint != 0 {
		flags += "hastunnel,"
	}
	if f&FlagIPv6TunnelEndpoint != 0 {
		flags += "ipv6tunnel,"
	}
	if f&FlagRemoteCluster != 0 {
		flags += "remotecluster,"
	}

	if flags == "" {
		return "<none>"
	}
	return strings.TrimSuffix(flags, ",")
}

const (
	// FlagSkipTunnel can be applied to a remote endpoint to signal that
	// packets destined for said endpoint shall not be forwarded through
	// a VXLAN/Geneve tunnel, regardless of Cilium's configuration.
	FlagSkipTunnel RemoteEndpointInfoFlags = 1 << iota
	// FlagHasTunnelEndpoint is set when the tunnel endpoint is not null. It
	// aims to simplify the logic compared to checking the IPv6 address.
	FlagHasTunnelEndpoint
	// FlagIPv6TunnelEndpoint is set when the tunnel endpoint IP address
	// is an IPv6 address.
	FlagIPv6TunnelEndpoint
	// FlagRemoteCluster is set when the node is in a remote cluster.
	// It's always unset when clustermesh is disabled or for pods.
	FlagRemoteCluster
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
		v.SecurityIdentity, v.Key, v.GetTunnelEndpoint(), v.Flags)
}

func (v *RemoteEndpointInfo) GetTunnelEndpoint() net.IP {
	if v.Flags&FlagIPv6TunnelEndpoint == 0 {
		return v.TunnelEndpoint[:4]
	}
	return v.TunnelEndpoint[:]
}

func (v *RemoteEndpointInfo) New() bpf.MapValue { return &RemoteEndpointInfo{} }

// RemoteEndpointInfoV1 implements the bpf.MapValue interface for the v1
// ipcache map value.
type RemoteEndpointInfoV1 struct {
	SecurityIdentity uint32     `align:"sec_identity"`
	TunnelEndpoint   types.IPv4 `align:"tunnel_endpoint"`
	_                uint16
	Key              uint8                   `align:"key"`
	Flags            RemoteEndpointInfoFlags `align:"flag_skip_tunnel"`
}

func (v *RemoteEndpointInfoV1) String() string {
	return fmt.Sprintf("identity=%d encryptkey=%d tunnelendpoint=%s flags=%s",
		v.SecurityIdentity, v.Key, v.TunnelEndpoint, v.Flags)
}

func (v *RemoteEndpointInfoV1) New() bpf.MapValue { return &RemoteEndpointInfoV1{} }

// NewValue returns a RemoteEndpointInfo based on the provided security
// identity, tunnel endpoint IP, IPsec key, and flags. The address family is
// automatically detected.
func NewValue(secID uint32, tunnelEndpoint net.IP, key uint8, flags RemoteEndpointInfoFlags) RemoteEndpointInfo {
	result := RemoteEndpointInfo{}

	result.SecurityIdentity = secID
	result.Key = key
	result.Flags = flags

	if tunnelEndpoint == nil {
		return result
	}

	result.Flags |= FlagHasTunnelEndpoint
	if ip4 := tunnelEndpoint.To4(); ip4 != nil {
		copy(result.TunnelEndpoint[:], ip4)
	} else {
		copy(result.TunnelEndpoint[:], tunnelEndpoint)
		result.Flags |= FlagIPv6TunnelEndpoint
	}

	return result
}

// Map represents an IPCache BPF map.
type Map struct {
	*bpf.Map
}

// OldMap represents an IPCache BPF map from a previous agent instance.
type OldMap struct {
	*bpf.Map
}

// OldV1Map represents a v1 IPCache BPF map.
type OldV1Map struct {
	*bpf.Map
}

// NewMap instantiates a Map.
func NewMap(
	logger *slog.Logger,
	lifecycle cell.Lifecycle,
	metricsRegistry *metrics.Registry,
	mapSpecRegistry *registry.MapSpecRegistry,
) (bpf.MapOut[*Map], bpf.MapOut[*OldMap]) {
	m := &Map{}
	mOld := &OldMap{}

	lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			spec, err := mapSpecRegistry.Get(Name)
			if err != nil {
				return err
			}

			// Open the existing map before its unpinned and replaced by the new map.
			// This old map will allow the local identity restorer to restore identities from the old map
			// and put them into the new map.
			mOld.Map, err = bpf.OpenMap(bpf.MapPath(logger, OldName), &Key{}, &RemoteEndpointInfoV1{})
			if err != nil {
				if !os.IsNotExist(err) {
					return fmt.Errorf("opening old ipcache map: %w", err)
				}
			}

			m.Map = bpf.NewMap(spec, &Key{}, &RemoteEndpointInfo{}).
				WithCache().WithPressureMetric(metricsRegistry).
				WithEvents(option.Config.GetEventBufferConfig(Name))

			// The ipcache is shared between endpoints. Unpin the old ipcache map created
			// by any previous instances of the agent to prevent new endpoints from
			// picking up the old map pin. The old ipcache will continue to be used by
			// loaded bpf programs, it will just no longer be updated by the agent.
			//
			// This is to allow existing endpoints that have not been regenerated yet to
			// continue using the existing ipcache until the endpoint is regenerated for
			// the first time and its bpf programs have been replaced. Existing endpoints
			// are using a policy map which is potentially out of sync as local identities
			// are re-allocated on startup.
			return m.Map.Recreate()
		},
		OnStop: func(_ cell.HookContext) error {
			return m.Map.Close()
		},
	})

	return bpf.NewMapOut(m), bpf.NewMapOut(mOld)
}

func OpenIPCacheMap(logger *slog.Logger) (*Map, error) {
	bpfMap, err := bpf.OpenMap(bpf.MapPath(logger, Name), &Key{}, &RemoteEndpointInfo{})
	return &Map{
		Map: bpfMap,
	}, err
}

// IPCacheMapV1 does the same as IPCacheMap but for the v1 ipcache map,
// from v1.18.
func OpenIPCacheMapV1(logger *slog.Logger) (*OldV1Map, error) {
	bpfMap, err := bpf.OpenMap(bpf.MapPath(logger, OldName), &Key{}, &RemoteEndpointInfoV1{})
	return &OldV1Map{
		Map: bpfMap,
	}, err
}
