// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bufio"
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
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
	// corresponds to whether the traffic is IPv6 or not
	PolicyVerdictNotifyFlagIsIPv6 = 0x4

	// PolicyVerdictNotifyFlagMatchType is the bit mask in Flags that
	// corresponds to the policy match type
	PolicyVerdictNotifyFlagMatchType = 0x38

	// PolicyVerdictNotifyFlagIsAudited is the bit mask in Flags that
	// corresponds to whether the traffic was allowed due to the audit mode
	PolicyVerdictNotifyFlagIsAudited = 0x40

	// PolicyVerdictNotifyFlagMatchTypeBitOffset is the bit offset in Flags that
	// corresponds to the policy match type
	PolicyVerdictNotifyFlagMatchTypeBitOffset = 3
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
	RemoteLabel identity.NumericIdentity
	Verdict     int32
	DstPort     uint16
	Proto       uint8
	Flags       uint8
	AuthType    uint8
	Pad1        uint8
	Pad2        uint16
	// data
}

// IsTrafficIngress returns true if this notify is for an ingress traffic
func (n *PolicyVerdictNotify) IsTrafficIngress() bool {
	return n.Flags&PolicyVerdictNotifyFlagDirection == api.PolicyIngress
}

// IsTrafficIPv6 returns true if this notify is for IPv6 traffic
func (n *PolicyVerdictNotify) IsTrafficIPv6() bool {
	return (n.Flags&PolicyVerdictNotifyFlagIsIPv6 > 0)
}

// GetPolicyMatchType returns how the traffic matched the policy
func (n *PolicyVerdictNotify) GetPolicyMatchType() api.PolicyMatchType {
	return api.PolicyMatchType((n.Flags & PolicyVerdictNotifyFlagMatchType) >>
		PolicyVerdictNotifyFlagMatchTypeBitOffset)
}

// IsTrafficAudited returns true if this notify is for traffic that
// was allowed due to the audit mode
func (n *PolicyVerdictNotify) IsTrafficAudited() bool {
	return (n.Flags&PolicyVerdictNotifyFlagIsAudited > 0)
}

// GetPolicyActionString returns the action string corresponding to the action
func GetPolicyActionString(verdict int32, audit bool) string {
	if audit {
		return "audit"
	}

	if verdict < 0 {
		return "deny"
	} else if verdict > 0 {
		return "redirect"
	}
	return "allow"
}

// GetAuthType returns string for the authentication method applied (for success verdict)
// or required (for drops).
func (n *PolicyVerdictNotify) GetAuthType() policy.AuthType {
	return policy.AuthType(n.AuthType)
}

// DumpInfo prints a summary of the policy notify messages.
func (n *PolicyVerdictNotify) DumpInfo(data []byte, numeric DisplayFormat) {
	buf := bufio.NewWriter(os.Stdout)
	dir := "egress"
	if n.IsTrafficIngress() {
		dir = "ingress"
	}
	fmt.Fprintf(buf, "Policy verdict log: flow %#x local EP ID %d", n.Hash, n.Source)
	if numeric {
		fmt.Fprintf(buf, ", remote ID %d", n.RemoteLabel)
	} else {
		fmt.Fprintf(buf, ", remote ID %s", n.RemoteLabel)
	}
	fmt.Fprintf(buf, ", proto %d, %s, action %s, auth: %s, match %s, %s\n", n.Proto, dir,
		GetPolicyActionString(n.Verdict, n.IsTrafficAudited()),
		n.GetAuthType(), n.GetPolicyMatchType(),
		GetConnectionSummary(data[PolicyVerdictNotifyLen:]))
	buf.Flush()
}
