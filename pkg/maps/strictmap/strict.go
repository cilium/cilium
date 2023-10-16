// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package strictmap

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// MaxEntries is the maximum number of keys that can be present in the
	// StrictModeMap.
	MaxEntries = 5

	// Name is the canonical name for the StrictModeMap on the filesystem.
	Name = "cilium_strict"
)

// key implements the bpf.MapKey interface.
//
// Must be in sync with struct ipcache_key in <bpf/lib/maps.h>
type key struct {
	Prefixlen uint32 `align:"lpm_key"`
	Pad1      uint16 `align:"pad1"`
	ClusterID uint8  `align:"cluster_id"`
	Family    uint8  `align:"family"`
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP types.IPv6 `align:"$union0"`
}

type value struct {
	Allow uint8  `align:"allow"`
	Pad1  uint8  `align:"pad1"`
	Port1 uint16 `align:"port1"`
	Port2 uint16 `align:"port2"`
}

const (
	sizeofStrictKey = int(unsafe.Sizeof(key{}))
	sizeofPrefixlen = int(unsafe.Sizeof(key{}.Prefixlen))
	sizeofIP        = int(unsafe.Sizeof(key{}.IP))

	staticPrefixBits = uint32(sizeofStrictKey-sizeofPrefixlen-sizeofIP) * 8
)

func (k key) String() string {
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

	prefixLen := int(k.Prefixlen - staticPrefixBits)
	clusterID := uint32(k.ClusterID)

	return cmtypes.PrefixClusterFrom(addr, prefixLen, cmtypes.WithClusterID(clusterID)).String()
}

func (k *key) New() bpf.MapKey { return &key{} }

// getPrefixLen determines the length that should be set inside the Key so that
// the lookup prefix is correct in the BPF map key. The specified 'prefixBits'
// indicates the number of bits in the IP that must match to match the entry in
// the BPF StrictModeMap.
func getPrefixLen(ipPrefixBits int) uint32 {
	return staticPrefixBits + uint32(ipPrefixBits)
}

// newKey returns an Key based on the provided CIDR and ClusterID.
// The address family is automatically detected
func newKey(ip netip.Prefix, clusterID uint8) (*key, error) {
	result := key{}

	ones := ip.Bits()
	if ones == -1 {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	if ip.Addr().Is4() {
		ipv4 := ip.Addr().As4()
		result.Family = bpf.EndpointKeyIPv4
		copy(result.IP[:], ipv4[:])
	} else if ip.Addr().Is6() {
		ipv6 := ip.Addr().As16()
		result.Family = bpf.EndpointKeyIPv6
		copy(result.IP[:], ipv6[:])
	} else {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	result.Prefixlen = getPrefixLen(ones)
	result.ClusterID = clusterID

	return &result, nil
}

func (v *value) String() string {
	return fmt.Sprintf("allowed=%d, AllowPorts=%d,%d", v.Allow, byteorder.NetworkToHost16(v.Port1), byteorder.NetworkToHost16(v.Port2))
}

func (v *value) New() bpf.MapValue { return &value{} }

var (
	// The StrictModeMap is a mapping of all CIDRs in the cluster to whether
	// strict encryption should be enforced.
	// It is a singleton; there is only one such map per agent.
	strict *bpf.Map
	once   = &sync.Once{}
)

// Create will create a strict map
func Create() error {
	once.Do(func() {
		strict = bpf.NewMap(
			Name,
			ebpf.LPMTrie,
			&key{},
			&value{},
			MaxEntries,
			bpf.BPF_F_NO_PREALLOC,
		).WithCache().
			WithEvents(option.Config.GetEventBufferConfig(Name))
	})

	return strict.OpenOrCreate()
}

// UpdateContext updates the encrypt state with ctxID to use the new keyID
func UpdateContext(ip netip.Prefix, clusterID uint8, allow uint8, port1 uint16, port2 uint16) error {
	k, err := newKey(ip, clusterID)
	if err != nil {
		return err
	}

	v := &value{
		Allow: allow,
		Port1: byteorder.HostToNetwork16(port1),
		Port2: byteorder.HostToNetwork16(port2),
	}

	return strict.Update(k, v)
}
