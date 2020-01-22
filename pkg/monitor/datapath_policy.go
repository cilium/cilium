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
	// PolicyNotifyLen is the amount of packet data provided in a Policy notification
	PolicyNotifyLen = 24

	// The values below are for parsing PolicyNotify. They need to be consistent
	// with what are defined in data plane.

	// PolicyNotifyFlagIsIPv6 is the bit mask in Flags that
	// corresponds to wether the traffic is IPv6 or not
	PolicyNotifyFlagIsIPv6 = 0x4

	// PolicyNotifyFlagDirection is the bit mask in Flags that
	// corresponds to the direction of a traffic
	PolicyNotifyFlagDirection = 0x3

	// PolicyIngress is the value of Flags&PolicyNotifyFlagDirection for ingress traffic
	PolicyIngress = 1

	// PolicyEgress is the value of Flags&PolicyNotifyFlagDirection for egress traffic
	PolicyEgress = 2

	// PolicyActionAllow is the value of Action for allowed traffic
	PolicyActionAllow = 1

	// PolicyActionDeny is the value of Action for denied traffic
	PolicyActionDeny = 2

	// PolicyMatchNone is the value of MatchType for traffic that doesn't match any rule
	PolicyMatchNone = 0

	// PolicyMatchL3 is the value of MatchType for traffic that matches a L3 rule
	PolicyMatchL3 = 1

	// PolicyMatchL4 is the value of MatchType for traffic that matches a L4 rule
	PolicyMatchL4 = 2

	// PolicyMatchL4All is the value of MatchType for traffic that matches a L4 rule with source identity any
	PolicyMatchL4All = 3

	// PolicyMatchAll is the value of MatchType for traffic that matches an allow all rule
	PolicyMatchAll = 4
)

// PolicyNotify is the message format of a policy notification in the BPF ring buffer
type PolicyNotify struct {
	Type        uint8
	SubType     uint8
	Source      uint16
	Hash        uint32
	OrigLen     uint32
	CapLen      uint16
	Version     uint16
	RemoteLabel uint32
	Action      uint8
	MatchType   uint8
	Flags       uint8
	Pad         uint8
	// data
}

// IsTrafficIngress returns whether this notify is for an ingress traffic
func (n *PolicyNotify) IsTrafficIngress() bool {
	return n.Flags&PolicyNotifyFlagDirection == PolicyIngress
}

// GetPolicyActionString returns the action string corresponding to the action
func GetPolicyActionString(action uint8) string {
	switch action {
	case PolicyActionAllow:
		return "allow"
	case PolicyActionDeny:
		return "deny"

	}
	return "unknown"
}

func getPolicyMatchingTypeString(matchType uint8) string {
	switch matchType {
	case PolicyMatchL3:
		return "L3"
	case PolicyMatchL4:
		return "L4"
	case PolicyMatchL4All:
		return "L4-all"
	case PolicyMatchAll:
		return "all"
	case PolicyMatchNone:
		return "none"

	}
	return "unknown"
}

// DumpInfo prints a summary of the policy notify messages.
func (n *PolicyNotify) DumpInfo(data []byte) {
	fmt.Printf("Policy log: flow %#x local EP ID %d, remote ID %d, ingress %v (flags %x), action %s, matching_type %s %s\n",
		n.Hash, n.Source, n.RemoteLabel, n.IsTrafficIngress(), n.Flags, GetPolicyActionString(n.Action),
		getPolicyMatchingTypeString(n.MatchType), GetConnectionSummary(data[PolicyNotifyLen:]))
}
