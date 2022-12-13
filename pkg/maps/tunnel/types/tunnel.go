// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

import (
	"net"

	bpfTypes "github.com/cilium/cilium/pkg/bpf/types"
	"github.com/cilium/cilium/pkg/types"
)

type TunnelEndpoint struct {
	bpfTypes.EndpointKey
}

// +k8s:deepcopy-gen=true
type TunnelIP struct {
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP     types.IPv6 `align:"$union0"`
	Family uint8      `align:"family"`
}

// ToIP converts the TunnelIP into a net.IP structure.
func (v TunnelIP) ToIP() net.IP {
	switch v.Family {
	case bpfTypes.EndpointKeyIPv4:
		return v.IP[:4]
	case bpfTypes.EndpointKeyIPv6:
		return v.IP[:]
	}
	return nil
}

type TunnelKey struct {
	TunnelIP
	ClusterID uint8  `align:"cluster_id"`
	Pad       uint16 `align:"pad"`
}

type TunnelValue struct {
	TunnelIP
	Key    uint8  `align:"key"`
	NodeID uint16 `align:"node_id"`
}
