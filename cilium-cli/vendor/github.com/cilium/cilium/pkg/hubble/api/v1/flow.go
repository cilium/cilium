// Copyright 2019 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

// FlowProtocol returns the protocol best describing the flow. If available,
// this is the L7 protocol name, then the L4 protocol name.
func FlowProtocol(flow Flow) string {
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

	case monitorAPI.MessageTypeDrop, monitorAPI.MessageTypeTrace:
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
			}
		}
		return "Unknown L4"
	}

	return "Unknown flow"
}
