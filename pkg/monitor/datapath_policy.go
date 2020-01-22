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

	PolicyNotifyFlagIsIPv6    = 0x4
	PolicyNotifyFlagDirection = 0x3
	PolicyIngress             = 1
	PolicyEgress              = 2
	PolicyActionAllow         = 1
	PolicyActionDeny          = 2
)

// DropNotify is the message format of a drop notification in the BPF ring buffer
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
	Flags       uint8
	Pads        uint16
	// data
}

func (n *PolicyNotify) IsTrafficIngress() bool {
	return n.Flags&PolicyNotifyFlagDirection == PolicyIngress
}

func GetPolicyActionString(action uint8) string {
	switch action {
	case PolicyActionAllow:
		return "allow"
	case PolicyActionDeny:
		return "deny"

	}
	return "unknown"
}

// DumpInfo prints a summary of the policy notify messages.
func (n *PolicyNotify) DumpInfo(data []byte) {
	fmt.Printf("Policy log: flow %#x local EP ID %d, remote ID %d, ingress %v (flags %x), action %s, %s\n",
		n.Hash, n.Source, n.RemoteLabel, n.IsTrafficIngress(), n.Flags, GetPolicyActionString(n.Action),
		GetConnectionSummary(data[PolicyNotifyLen:]))
}
