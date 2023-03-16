// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

var Cell = cell.Provide(NewMapInterface)

type MapInterface interface {
	Delete(key *Key) error
	DumpWithCallback(cb DumpCallback) error
	DumpOldState(cb DumpCallback) error
	Update(key *Key, value *RemoteEndpointInfo) error
}

type DumpCallback func(key *Key, value *RemoteEndpointInfo)

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
	SecurityIdentity uint32     `align:"sec_label"`
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
	m bpf.Map

	oldState []kv
}

type kv struct {
	key   *Key
	value *RemoteEndpointInfo
}

func NewMap() *Map {
	inner := bpf.NewMap(
		Name,
		bpf.MapTypeLPMTrie,
		&Key{},
		int(unsafe.Sizeof(Key{})),
		&RemoteEndpointInfo{},
		int(unsafe.Sizeof(RemoteEndpointInfo{})),
		MaxEntries,
		bpf.BPF_F_NO_PREALLOC, 0,
		bpf.ConvertKeyValue)

	return &Map{
		m: *inner.WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(Name)),
	}
}

// NewMapInterface instantiates a Map.
func NewMapInterface(lifecycle hive.Lifecycle, config *option.DaemonConfig) MapInterface {
	m := NewMap()

	lifecycle.Append(hive.Hook{
		OnStart: func(hc hive.HookContext) error {
			if config.RestoreState {
				// There are a number of components that want to re-use the existing state of the IPCache.
				// So save that old state in memory until it is needed, and proceed with recreating the map.
				if err := m.saveOldState(); err != nil {
					return fmt.Errorf("saveOldState: %w", err)
				}
			}

			// The ipcache is shared between endpoints. Recreating the map
			// to allow existing endpoints that have not been regenerated yet
			// to continue using the existing ipcache until the endpoint is
			// regenerated for the first time. Existing endpoints are using a
			// policy map which is potentially out of sync as local identities are
			// re-allocated on startup. Recreating allows to continue using the
			// old version until regeneration. Note that the old version is not
			// updated with new identities. This is fine as any new identity
			// appearing would require a regeneration of the endpoint anyway in
			// order for the endpoint to gain the privilege of communication.
			return m.m.Recreate()
		},
	})

	return m
}

// Open the existing map (if any), and save the state of that map.
// This data can be used by other components to restore partial state which allows the agent to restart with minimal
// disruption.
func (m *Map) saveOldState() error {
	isNew, err := m.m.OpenOrCreate()
	if err != nil {
		return fmt.Errorf("OpenOrCreate: %w", err)
	}

	if !isNew {
		err = m.DumpWithCallback(func(key *Key, value *RemoteEndpointInfo) {
			m.oldState = append(m.oldState, kv{
				key:   key.DeepCopy(),
				value: value.DeepCopy(),
			})
		})

		if err != nil {
			_ = m.m.Close()
			return fmt.Errorf("DumpWithCallback: %w", err)
		}
	}

	if err := m.m.Close(); err != nil {
		return fmt.Errorf("Close: %w", err)
	}

	return nil
}

// Dump dumps the map state, without recreating it.
func (m *Map) Dump(hash map[string][]string) error {
	_, err := m.m.OpenOrCreate()
	if err != nil {
		return fmt.Errorf("open or create: %w", err)
	}

	defer m.m.Close()

	return m.m.Dump(hash)
}

func (m *Map) Delete(key *Key) error {
	return m.m.Delete(key)
}

func (m *Map) DumpWithCallback(cb DumpCallback) error {
	return m.m.DumpWithCallback(func(key bpf.MapKey, value bpf.MapValue) {
		cb(key.(*Key), value.(*RemoteEndpointInfo))
	})
}

func (m *Map) Update(key *Key, value *RemoteEndpointInfo) error {
	return m.m.Update(key, value)
}

// DumpOldState dumps the state of the IPCache map from before it was recreated during initialization.
// Calling this function also erase the that old state.
func (m *Map) DumpOldState(cb DumpCallback) error {
	for _, kv := range m.oldState {
		cb(kv.key, kv.value)
	}

	// Let the old state be GC'ed, no need to keep it around.
	m.oldState = nil

	return nil
}

// GetMaxPrefixLengths determines how many unique prefix lengths are supported
// simultaneously based on the underlying BPF map type in use.
func GetMaxPrefixLengths() (ipv6, ipv4 int) {
	return net.IPv6len*8 + 1, net.IPv4len*8 + 1
}
