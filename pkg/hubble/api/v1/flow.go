// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package v1

import (
	pb "github.com/cilium/cilium/api/v1/flow"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

// FlowProtocol returns the protocol best describing the flow. If available,
// this is the L7 protocol name, then the L4 protocol name.
func FlowProtocol(flow *pb.Flow) string {
	switch flow.GetEventType().Type {
	case monitorAPI.MessageTypeAccessLog:
		if l7 := flow.GetL7(); l7 != nil {
			switch {
			case l7.GetDns() != nil:
				return "DNS"
			case l7.GetHttp() != nil:
				return "HTTP"
			case l7.GetKafka() != nil:
				return "Kafka"
			}
		}
		return "Unknown L7"

	case monitorAPI.MessageTypeDrop, monitorAPI.MessageTypeTrace,
		monitorAPI.MessageTypePolicyVerdict, monitorAPI.MessageTypeCapture:
		if l4 := flow.GetL4(); l4 != nil {
			switch {
			case l4.GetTCP() != nil:
				return "TCP"
			case l4.GetUDP() != nil:
				return "UDP"
			case l4.GetICMPv4() != nil:
				return "ICMPv4"
			case l4.GetICMPv6() != nil:
				return "ICMPv6"
			case l4.GetSCTP() != nil:
				return "SCTP"
			}
		}
		return "Unknown L4"
	}

	return "Unknown flow"
}
