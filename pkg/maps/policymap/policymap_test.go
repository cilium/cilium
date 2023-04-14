// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"testing"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/policy/trafficdirection"
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
