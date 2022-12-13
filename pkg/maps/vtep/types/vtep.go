// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

import (
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/types"
)

type Key struct {
	IP types.IPv4 `align:"vtep_ip"`
}

type VtepEndpointInfo struct {
	VtepMAC        mac.Uint64MAC `align:"vtep_mac"`
	TunnelEndpoint types.IPv4    `align:"tunnel_endpoint"`
}
