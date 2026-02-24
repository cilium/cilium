// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"net"

	"github.com/cilium/cilium/api/v1/flow"
)

// Ethernet tracks source/destination MAC addresses.
type Ethernet struct {
	Source      net.HardwareAddr `json:"source,omitempty"`
	Destination net.HardwareAddr `json:"destination,omitempty"`
}

func (e Ethernet) toProto() *flow.Ethernet {
	if e.isEmpty() {
		return nil
	}
	return &flow.Ethernet{
		Source:      e.Source.String(),
		Destination: e.Destination.String(),
	}
}

func protoToEther(e *flow.Ethernet) Ethernet {
	if e == nil {
		return Ethernet{}
	}

	s, _ := net.ParseMAC(e.Source)
	d, _ := net.ParseMAC(e.Destination)

	return Ethernet{
		Source:      s,
		Destination: d,
	}
}

func (e Ethernet) isEmpty() bool {
	return len(e.Source) == 0 && len(e.Destination) == 0
}
