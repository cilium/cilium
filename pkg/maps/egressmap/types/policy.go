// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

import "github.com/cilium/cilium/pkg/types"

type EgressPolicyKey4 struct {
	// PrefixLen is full 32 bits of SourceIP + DestCIDR's mask bits
	PrefixLen uint32 `align:"lpm_key"`

	SourceIP types.IPv4 `align:"saddr"`
	DestCIDR types.IPv4 `align:"daddr"`
}

type EgressPolicyVal4 struct {
	EgressIP  types.IPv4 `align:"egress_ip"`
	GatewayIP types.IPv4 `align:"gateway_ip"`
}
