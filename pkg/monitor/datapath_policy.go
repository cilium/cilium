// Copyright 2016-2017 Authors of Cilium
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

package monitor

import (
	"fmt"
)

const (
	// PolicyVerdictNotifyLen is the amount of packet data provided in a Policy notification
	PolicyVerdictNotifyLen = 32

	// The values below are for parsing PolicyVerdictNotify. They need to be consistent
	// with what are defined in data plane.

	// PolicyVerdictNotifyFlagDirection is the bit mask in Flags that
	// corresponds to the direction of a traffic
	PolicyVerdictNotifyFlagDirection = 0x3

	// PolicyVerdictNotifyFlagIsIPv6 is the bit mask in Flags that
	// corresponds to wether the traffic is IPv6 or not
	PolicyVerdictNotifyFlagIsIPv6 = 0x4

	// PolicyVerdictNotifyFlagMatchType is the bit mask in Flags that
	// corresponds to the policy match type
	PolicyVerdictNotifyFlagMatchType = 0x38

	// PolicyVerdictNotifyFlagMatchTypeBitOffset is the bit offset in Flags that
	// corresponds to the policy match type
	PolicyVerdictNotifyFlagMatchTypeBitOffset = 3

	// PolicyIngress is the value of Flags&PolicyNotifyFlagDirection for ingress traffic
	PolicyIngress = 1

	// PolicyEgress is the value of Flags&PolicyNotifyFlagDirection for egress traffic
	PolicyEgress = 2

	// PolicyMatchNone is the value of MatchType indicatating no policy match
	PolicyMatchNone = 0

	// PolicyMatchL3Only is the value of MatchType indicating a L3-only match
	PolicyMatchL3Only = 1

	// PolicyMatchL3L4 is the value of MatchType indicating a L3+L4 match
	PolicyMatchL3L4 = 2

	// PolicyMatchL4Only is the value of MatchType indicating a L4-only match
	PolicyMatchL4Only = 3

	// PolicyMatchAll is the value of MatchType indicating an allow-all match
	PolicyMatchAll = 4
)

// PolicyVerdictNotify is the message format of a policy verdict notification in the bpf ring buffer
type PolicyVerdictNotify struct {
	Type        uint8
	SubType     uint8
	Source      uint16
	Hash        uint32
	OrigLen     uint32
	CapLen      uint16
	Version     uint16
	RemoteLabel uint32
	Verdict     int32
	DstPort     uint16
	Proto       uint8
	Flags       uint8
	Pad2        uint32
	// data
}

// IsTrafficIngress returns true if this notify is for an ingress traffic
func (n *PolicyVerdictNotify) IsTrafficIngress() bool {
	return n.Flags&PolicyVerdictNotifyFlagDirection == PolicyIngress
}

// IsTrafficIPv6 returns true if this notify is for IPv6 traffic
func (n *PolicyVerdictNotify) IsTrafficIPv6() bool {
	return (n.Flags&PolicyVerdictNotifyFlagIsIPv6 > 0)
}

// GetPolicyActionString returns the action string corresponding to the action
func GetPolicyActionString(verdict int32) string {
	if verdict < 0 {
		return "deny"
	} else if verdict > 0 {
		return "redirect"
	}
	return "allow"
}

func getPolicyMatchTypeString(flag uint8) string {
	matchType := (flag & PolicyVerdictNotifyFlagMatchType) >>
		PolicyVerdictNotifyFlagMatchTypeBitOffset
	switch matchType {
	case PolicyMatchL3Only:
		return "L3-Only"
	case PolicyMatchL3L4:
		return "L3-L4"
	case PolicyMatchL4Only:
		return "L4-Only"
	case PolicyMatchAll:
		return "all"
	case PolicyMatchNone:
		return "none"

	}
	return "unknown"
}

// DumpInfo prints a summary of the policy notify messages.
func (n *PolicyVerdictNotify) DumpInfo(data []byte) {
	fmt.Printf("Policy verdict log: flow %#x local EP ID %d, remote ID %d, dst port %d, proto %d, ingress %v, action %s, match %s, %s\n",
		n.Hash, n.Source, n.RemoteLabel, n.DstPort, n.Proto, n.IsTrafficIngress(), GetPolicyActionString(n.Verdict),
		getPolicyMatchTypeString(n.Flags), GetConnectionSummary(data[PolicyVerdictNotifyLen:]))
}
