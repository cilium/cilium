// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

import "github.com/cilium/cilium/pkg/types"

type Key struct {
	Prefixlen uint32 `align:"lpm_key"`
	Pad1      uint16 `align:"pad1"`
	ClusterID uint8  `align:"cluster_id"`
	Family    uint8  `align:"family"`
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP types.IPv6 `align:"$union0"`
}

type RemoteEndpointInfo struct {
	SecurityIdentity uint32     `align:"sec_label"`
	TunnelEndpoint   types.IPv4 `align:"tunnel_endpoint"`
	NodeID           uint16     `align:"node_id"`
	Key              uint8      `align:"key"`
}
