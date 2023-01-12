// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"fmt"
	"net"
	"unsafe"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	ippkg "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/types"
)

// Must be in sync with ENDPOINT_KEY_* in <bpf/lib/common.h>
const (
	EndpointKeyIPv4 uint8 = 1
	EndpointKeyIPv6 uint8 = 2
)

// EndpointKey represents the key value of the endpoints BPF map
//
// Must be in sync with struct endpoint_key in <bpf/lib/common.h>
// +k8s:deepcopy-gen=true
type EndpointKey struct {
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP        types.IPv6 `align:"$union0"`
	Family    uint8      `align:"family"`
	Key       uint8      `align:"key"`
	ClusterID uint8      `align:"cluster_id"`
	Pad       uint8      `align:"pad"`
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *EndpointKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetValuePtr returns the unsafe pointer to the BPF key for users that
// use EndpointKey as a value in bpf maps
func (k *EndpointKey) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(k) }

// NewEndpointKey returns an EndpointKey based on the provided IP address. The
// address family is automatically detected.
func NewEndpointKey(ip net.IP, clusterID uint8) EndpointKey {
	result := EndpointKey{}

	if ip4 := ip.To4(); ip4 != nil {
		result.Family = EndpointKeyIPv4
		copy(result.IP[:], ip4)
	} else {
		result.Family = EndpointKeyIPv6
		copy(result.IP[:], ip)
	}
	result.Key = 0
	result.ClusterID = clusterID

	return result
}

// ToIP converts the EndpointKey into a net.IP structure.
func (k EndpointKey) ToIP() net.IP {
	switch k.Family {
	case EndpointKeyIPv4:
		return k.IP[:4]
	case EndpointKeyIPv6:
		return k.IP[:]
	}
	return nil
}

// String provides a string representation of the EndpointKey.
func (k EndpointKey) String() string {
	if ip := k.ToIP(); ip != nil {
		addrCluster := cmtypes.AddrClusterFrom(
			ippkg.MustAddrFromIP(ip),
			uint32(k.ClusterID),
		)
		return addrCluster.String() + ":" + fmt.Sprintf("%d", k.Key)
	}
	return "nil"
}
