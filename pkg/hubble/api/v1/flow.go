// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package v1

import (
	"github.com/cilium/cilium/pkg/hubble/build"
	"github.com/cilium/cilium/pkg/hubble/ir"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

// FlowEmitter is an identifier for the source system that emits a flow.
const FlowEmitter = "Hubble"

// FlowEmitterVersion is the version of the component that emits flows.
var FlowEmitterVersion = build.ServerVersion.SemVer()

// FlowProtocol returns the protocol best describing the flow. If available,
// this is the L7 protocol name, then the L4 protocol name.
func FlowProtocol(flow *ir.Flow) string {
	switch flow.EventType.Type {
	case monitorAPI.MessageTypeAccessLog:
		if !flow.L7.IsEmpty() {
			switch {
			case !flow.L7.DNS.IsEmpty():
				return "DNS"
			case !flow.L7.HTTP.IsEmpty():
				return "HTTP"
			case !flow.L7.Kafka.IsEmpty():
				return "Kafka"
			}
		}
		return "Unknown L7"

	case monitorAPI.MessageTypeDrop, monitorAPI.MessageTypeTrace,
		monitorAPI.MessageTypePolicyVerdict, monitorAPI.MessageTypeCapture:
		if !flow.L4.IsEmpty() {
			switch {
			case !flow.L4.TCP.IsEmpty():
				return "TCP"
			case !flow.L4.UDP.IsEmpty():
				return "UDP"
			case !flow.L4.ICMPv4.IsEmpty():
				return "ICMPv4"
			case !flow.L4.ICMPv6.IsEmpty():
				return "ICMPv6"
			case !flow.L4.SCTP.IsEmpty():
				return "SCTP"
			case !flow.L4.VRRP.IsEmpty():
				return "VRRP"
			case !flow.L4.IGMP.IsEmpty():
				return "IGMP"
			}
		}
		return "Unknown L4"
	}

	return "Unknown flow"
}
