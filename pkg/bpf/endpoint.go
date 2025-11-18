// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"fmt"
	"net/netip"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/types"
)

// Must be in sync with ENDPOINT_KEY_* in <bpf/lib/eps.h>
const (
	EndpointKeyIPv4 uint8 = 1
	EndpointKeyIPv6 uint8 = 2
)

// EndpointKey represents the key value of the endpoints BPF map
//
// Must be in sync with struct endpoint_key in <bpf/lib/eps.h>
type EndpointKey struct {
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP        types.IPv6 `align:"$union0"`
	Family    uint8      `align:"family"`
	Key       uint8      `align:"key"`
	ClusterID uint16     `align:"cluster_id"`
}

// NewEndpointKey returns an EndpointKey based on the provided IP address. The
// address family is automatically detected.
func NewEndpointKey(addr netip.Addr, clusterID uint16) EndpointKey {
	result := EndpointKey{}

	if addr.Is4() {
		result.Family = EndpointKeyIPv4
	} else if addr.Is6() {
		result.Family = EndpointKeyIPv6
	}
	copy(result.IP[:], addr.AsSlice())
	result.Key = 0
	result.ClusterID = clusterID

	return result
}

// ToIP converts the EndpointKey into a netip.Addr.
func (k EndpointKey) ToAddr() netip.Addr {
	switch k.Family {
	case EndpointKeyIPv4:
		return netip.AddrFrom4([4]byte(k.IP[:4]))
	case EndpointKeyIPv6:
		return netip.AddrFrom16([16]byte(k.IP[:]))
	}
	return netip.Addr{}
}

// String provides a string representation of the EndpointKey.
func (k EndpointKey) String() string {
	if addr := k.ToAddr(); addr.IsValid() {
		addrCluster := cmtypes.AddrClusterFrom(
			addr,
			uint32(k.ClusterID),
		)
		return addrCluster.String() + ":" + fmt.Sprintf("%d", k.Key)
	}
	return "nil"
}
