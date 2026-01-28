// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bufio"
	"encoding/binary"
	"fmt"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
)

const (
	// PolicyVerdictNotifyLen is the length (in bytes) of the PolicyVerdictNotify message
	// header, i.e. the offset of the packet data provided in a policy verdict notification.
	PolicyVerdictNotifyLen = 40

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

	// PolicyVerdictNotifyFlagIsL3 is the bit mask in Flags that
	// corresponds to whether the traffic is from a L3 device or not
	PolicyVerdictNotifyFlagIsL3 = 0x80

	// PolicyVerdictNotifyFlagMatchTypeBitOffset is the bit offset in Flags that
	// corresponds to the policy match type
	PolicyVerdictNotifyFlagMatchTypeBitOffset = 3
)

const PolicyVerdictExtensionDisabled = 0

var (
	// Downstream projects should register introduced extensions length so that
	// the upstream parsing code still works even if the DP events contain
	// additional fields.
	policyVerdictExtensionLengthFromVersion = map[uint8]uint{
		// The PolicyVerdictExtension is intended for downstream extensions and
		// should not be used in the upstream project.
		PolicyVerdictExtensionDisabled: 0,
	}
)

// PolicyVerdictNotify is the message format of a policy verdict notification in the bpf ring buffer
type PolicyVerdictNotify struct {
	Type        uint8                    `align:"type"`
	SubType     uint8                    `align:"subtype"`
	Source      uint16                   `align:"source"`
	Hash        uint32                   `align:"hash"`
	OrigLen     uint32                   `align:"len_orig"`
	CapLen      uint16                   `align:"len_cap"`
	Version     uint8                    `align:"version"`
	ExtVersion  uint8                    `align:"ext_version"`
	RemoteLabel identity.NumericIdentity `align:"remote_label"`
	Verdict     int32                    `align:"verdict"`
	DstPort     uint16                   `align:"dst_port"`
	Proto       uint8                    `align:"proto"`
	Flags       uint8                    `align:"dir"`
	AuthType    uint8                    `align:"auth_type"`
	_           [3]uint8                 `align:"pad1"`
	Cookie      uint32                   `align:"cookie"`
	_           uint32                   `align:"pad2"`
	// data
}

// Dump prints the message according to the verbosity level specified
func (pn *PolicyVerdictNotify) Dump(args *api.DumpArgs) {
	pn.DumpInfo(args.Buf, args.Data, args.Format)
}

// GetSrc retrieves the source endpoint for the message.
func (n *PolicyVerdictNotify) GetSrc() uint16 {
	return n.Source
}

// GetDst retrieves the security identity for the message.
// `POLICY_INGRESS` -> `RemoteLabel` is the src security identity.
// `POLICY_EGRESS` -> `RemoteLabel` is the dst security identity.
func (n *PolicyVerdictNotify) GetDst() uint16 {
	return uint16(n.RemoteLabel)
}

// Decode decodes the message in 'data' into the struct.
func (n *PolicyVerdictNotify) Decode(data []byte) error {
	if l := len(data); l < PolicyVerdictNotifyLen {
		return fmt.Errorf("unexpected PolicyVerdictNotify data length, expected %d but got %d", PolicyVerdictNotifyLen, l)
	}

	n.Type = data[0]
	n.SubType = data[1]
	n.Source = binary.NativeEndian.Uint16(data[2:4])
	n.Hash = binary.NativeEndian.Uint32(data[4:8])
	n.OrigLen = binary.NativeEndian.Uint32(data[8:12])
	n.CapLen = binary.NativeEndian.Uint16(data[12:14])
	n.Version = data[14]
	n.ExtVersion = data[15]
	n.RemoteLabel = identity.NumericIdentity(binary.NativeEndian.Uint32(data[16:20]))
	n.Verdict = int32(binary.NativeEndian.Uint32(data[20:24]))
	n.DstPort = binary.NativeEndian.Uint16(data[24:26])
	n.Proto = data[26]
	n.Flags = data[27]
	n.AuthType = data[28]
	n.Cookie = binary.NativeEndian.Uint32(data[32:36])

	return nil
}

// IsTrafficIngress returns true if this notify is for an ingress traffic
func (n *PolicyVerdictNotify) IsTrafficIngress() bool {
	return n.Flags&PolicyVerdictNotifyFlagDirection == api.PolicyIngress
}

// IsTrafficIPv6 returns true if this notify is for IPv6 traffic
func (n *PolicyVerdictNotify) IsTrafficIPv6() bool {
	return (n.Flags&PolicyVerdictNotifyFlagIsIPv6 > 0)
}

// IsTrafficL3Device returns true if this notify is from a L3 device
func (n *PolicyVerdictNotify) IsTrafficL3Device() bool {
	return (n.Flags&PolicyVerdictNotifyFlagIsL3 > 0)
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

// DataOffset returns the offset from the beginning of PolicyVerdictNotify where the
// notification data begins.
func (n *PolicyVerdictNotify) DataOffset() uint {
	return PolicyVerdictNotifyLen + policyVerdictExtensionLengthFromVersion[n.ExtVersion]
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
func (n *PolicyVerdictNotify) DumpInfo(buf *bufio.Writer, data []byte, numeric api.DisplayFormat) {
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
		GetConnectionSummary(data[n.DataOffset():], &decodeOpts{IsL3Device: n.IsTrafficL3Device(), IsIPv6: n.IsTrafficIPv6()}))
}
