// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
)

func Test(t *testing.T) {
	TestingT(t)
}

type PolicyMapTestSuite struct{}

var _ = Suite(&PolicyMapTestSuite{})

func (pm *PolicyMapTestSuite) TestPolicyEntriesDump_Less(c *C) {
	type args struct {
		i int
		j int
	}
	tests := []struct {
		name string
		p    PolicyEntriesDump
		args args
		want bool
	}{
		{
			name: "Same element",
			p: PolicyEntriesDump{
				{
					Key: PolicyKey{
						Identity:         uint32(0),
						DestPortNetwork:  0,
						Nexthdr:          0,
						TrafficDirection: uint8(trafficdirection.Ingress),
					},
				},
			},
			args: args{
				i: 0,
				j: 0,
			},
			want: false,
		},
		{
			name: "Element #0 is less than #1 because identity is smaller",
			p: PolicyEntriesDump{
				{
					Key: PolicyKey{
						Identity:         uint32(0),
						DestPortNetwork:  0,
						Nexthdr:          0,
						TrafficDirection: uint8(trafficdirection.Ingress),
					},
				},
				{
					Key: PolicyKey{
						Identity:         uint32(1),
						DestPortNetwork:  0,
						Nexthdr:          0,
						TrafficDirection: uint8(trafficdirection.Ingress),
					},
				},
			},
			args: args{
				i: 0,
				j: 1,
			},
			want: true,
		},
		{
			name: "Element #0 is less than #1 because TrafficDirection is smaller",
			p: PolicyEntriesDump{
				{
					Key: PolicyKey{
						Identity:         uint32(0),
						DestPortNetwork:  0,
						Nexthdr:          0,
						TrafficDirection: uint8(trafficdirection.Ingress),
					},
				},
				{
					Key: PolicyKey{
						Identity:         uint32(1),
						DestPortNetwork:  0,
						Nexthdr:          0,
						TrafficDirection: uint8(trafficdirection.Egress),
					},
				},
			},
			args: args{
				i: 0,
				j: 1,
			},
			want: true,
		},
		{
			name: "Element #0 is not less than #1 because Identity is bigger",
			p: PolicyEntriesDump{
				{
					Key: PolicyKey{
						Identity:         uint32(1),
						DestPortNetwork:  0,
						Nexthdr:          0,
						TrafficDirection: uint8(trafficdirection.Egress),
					},
				},
				{
					Key: PolicyKey{
						Identity:         uint32(0),
						DestPortNetwork:  0,
						Nexthdr:          0,
						TrafficDirection: uint8(trafficdirection.Egress),
					},
				},
			},
			args: args{
				i: 0,
				j: 1,
			},
			want: false,
		},
		{
			name: "Element #0 is greater than #1 because it is not an allow (denies take precedence)",
			p: PolicyEntriesDump{
				{
					Key: PolicyKey{
						Identity:         uint32(1),
						DestPortNetwork:  0,
						Nexthdr:          0,
						TrafficDirection: uint8(trafficdirection.Egress),
					},
				},
				{
					Key: PolicyKey{
						Identity:         uint32(0),
						DestPortNetwork:  0,
						Nexthdr:          0,
						TrafficDirection: uint8(trafficdirection.Egress),
					},
					PolicyEntry: PolicyEntry{
						Flags: policyFlagDeny,
					},
				},
			},
			args: args{
				i: 0,
				j: 1,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		got := tt.p.Less(tt.args.i, tt.args.j)
		c.Assert(got, Equals, tt.want, Commentf("Test Name: %s", tt.name))
	}
}

type opType int

const (
	allow opType = iota
	deny
)

type direction int

const (
	ingress direction = iota
	egress
)

func (pm *PolicyMapTestSuite) TestPolicyMapWildcarding(c *C) {
	type args struct {
		op               opType
		id               int
		dport            int
		proto            int
		trafficDirection direction
		authType         int
		proxyPort        int
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Allow, no wildcarding, no redirection",
			args: args{allow, 42, 80, 6, ingress, 0, 0},
		},
		{
			name: "Allow, no wildcarding, with redirection and auth",
			args: args{allow, 42, 80, 6, ingress, 1, 23767},
		},
		{
			name: "Allow, wildcarded port, no redirection",
			args: args{allow, 42, 0, 6, ingress, 0, 0},
		},
		{
			name: "Allow, wildcarded protocol, no redirection",
			args: args{allow, 42, 0, 0, ingress, 0, 0},
		},
		{
			name: "Deny, no wildcarding, no redirection",
			args: args{deny, 42, 80, 6, ingress, 0, 0},
		},
		{
			name: "Deny, no wildcarding, no redirection",
			args: args{deny, 42, 80, 6, ingress, 0, 0},
		},
		{
			name: "Deny, wildcarded port, no redirection",
			args: args{deny, 42, 0, 6, ingress, 0, 0},
		},
		{
			name: "Deny, wildcarded protocol, no redirection",
			args: args{deny, 42, 0, 0, ingress, 0, 0},
		},
		{
			name: "Allow, wildcarded id, no port wildcarding, no redirection",
			args: args{allow, 0, 80, 6, ingress, 0, 0},
		},
		{
			name: "Allow, wildcarded id, no port wildcarding, with redirection and auth",
			args: args{allow, 0, 80, 6, ingress, 1, 23767},
		},
		{
			name: "Allow, wildcarded id, wildcarded port, no redirection",
			args: args{allow, 0, 0, 6, ingress, 0, 0},
		},
		{
			name: "Allow, wildcarded id, wildcarded protocol, no redirection",
			args: args{allow, 0, 0, 0, ingress, 0, 0},
		},
		{
			name: "Deny, wildcarded id, no port wildcarding, no redirection",
			args: args{deny, 0, 80, 6, ingress, 0, 0},
		},
		{
			name: "Deny, wildcarded id, no port wildcarding, no redirection",
			args: args{deny, 0, 80, 6, ingress, 0, 0},
		},
		{
			name: "Deny, wildcarded id, wildcarded port, no redirection",
			args: args{deny, 0, 0, 6, ingress, 0, 0},
		},
		{
			name: "Deny, wildcarded id, wildcarded protocol, no redirection",
			args: args{deny, 0, 0, 0, ingress, 0, 0},
		},
	}
	for _, tt := range tests {
		// Validate test data
		if tt.args.proto == 0 {
			c.Assert(tt.args.dport, Equals, 0,
				Commentf("Test: %s data error: dport must be wildcarded when protocol is wildcarded", tt.name))
		}
		if tt.args.dport == 0 {
			c.Assert(tt.args.proxyPort, Equals, 0,
				Commentf("Test: %s data error: proxyPort must be zero when dport is wildcarded", tt.name))
		}
		if tt.args.op == deny {
			c.Assert(tt.args.proxyPort, Equals, 0, Commentf("Test: %s data error: proxyPort must be zero with a deny key", tt.name))
			c.Assert(tt.args.authType, Equals, 0, Commentf("Test: %s data error: authType must be zero with a deny key", tt.name))
		}

		// Get key
		key := newKey(uint32(tt.args.id), uint16(tt.args.dport), u8proto.U8proto(tt.args.proto),
			trafficdirection.TrafficDirection(tt.args.trafficDirection))

		// Compure entry & validate key and entry
		var entry PolicyEntry
		switch tt.args.op {
		case allow:
			entry = newAllowEntry(key, uint8(tt.args.authType), uint16(tt.args.proxyPort))

			c.Assert(entry.Flags&policyFlagDeny, Equals, policyEntryFlags(0))
			c.Assert(entry.AuthType, Equals, uint8(tt.args.authType))
			c.Assert(byteorder.NetworkToHost16(entry.ProxyPortNetwork), Equals, uint16(tt.args.proxyPort))
		case deny:
			entry = newDenyEntry(key)

			c.Assert(entry.Flags&policyFlagDeny, Equals, policyFlagDeny)
			c.Assert(entry.AuthType, Equals, uint8(0))
			c.Assert(entry.ProxyPortNetwork, Equals, uint16(0))
		}

		c.Assert(key.Identity, Equals, uint32(tt.args.id))
		c.Assert(key.Nexthdr, Equals, uint8(tt.args.proto))
		if key.Nexthdr == 0 {
			c.Assert(entry.Flags&policyFlagWildcardNexthdr, Equals, policyFlagWildcardNexthdr)
			c.Assert(key.DestPortNetwork, Equals, uint16(0))
			c.Assert(entry.Flags&policyFlagWildcardDestPort, Equals, policyFlagWildcardDestPort)
			c.Assert(key.Prefixlen, Equals, StaticPrefixBits)
		} else {
			c.Assert(entry.Flags&policyFlagWildcardNexthdr, Equals, policyEntryFlags(0))
			if key.DestPortNetwork == 0 {
				c.Assert(entry.Flags&policyFlagWildcardDestPort, Equals, policyFlagWildcardDestPort)
				c.Assert(key.Prefixlen, Equals, StaticPrefixBits+NexthdrBits)
			} else {
				c.Assert(byteorder.NetworkToHost16(key.DestPortNetwork), Equals, uint16(tt.args.dport))
				c.Assert(entry.Flags&policyFlagWildcardDestPort, Equals, policyEntryFlags(0))
				c.Assert(key.Prefixlen, Equals, StaticPrefixBits+FullPrefixBits)
			}
		}
	}
}
