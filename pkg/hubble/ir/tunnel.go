// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import "github.com/cilium/cilium/api/v1/flow"

// Tunnel tracks flow tunnel information.
type Tunnel struct {
	IP       IP                   `json:"ip,omitempty"`
	L4       Layer4               `json:"l4,omitempty"`
	Vni      uint32               `json:"vni,omitempty"`
	Protocol flow.Tunnel_Protocol `json:"protocol,omitempty"`
}

// IsEmpty returns true if target has no data.
// NOTE: Leaving protocol and vni fields unchecked since if no other fields are set the Tunnel should be deemed empty.
func (t Tunnel) IsEmpty() bool {
	return t.IP.IsEmpty() && t.L4.IsEmpty()
}

func (t Tunnel) toProto() *flow.Tunnel {
	if t.IsEmpty() {
		return nil
	}

	return &flow.Tunnel{
		IP:       t.IP.toProto(),
		L4:       t.L4.toProto(),
		Vni:      t.Vni,
		Protocol: t.Protocol,
	}
}

func protoToTunnel(t *flow.Tunnel) Tunnel {
	if t == nil {
		return Tunnel{}
	}

	return Tunnel{
		IP:       protoToIP(t.GetIP()),
		L4:       protoToL4(t.GetL4()),
		Vni:      t.GetVni(),
		Protocol: t.Protocol,
	}
}
