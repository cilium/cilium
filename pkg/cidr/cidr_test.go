// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cidr

import (
	"net"
	"testing"

	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
)

// Hook up gocheck into the "go test" runner.
type CidrTestSuite struct{}

var _ = check.Suite(&CidrTestSuite{})

func Test(t *testing.T) {
	check.TestingT(t)
}

func (t *CidrTestSuite) TestNilDeepCopy(c *check.C) {
	var c1 *CIDR
	c.Assert(c1.DeepCopy(), check.IsNil)
}

func (t *CidrTestSuite) TestDeepCopy(c *check.C) {
	_, ipnet, err := net.ParseCIDR("1.1.1.1/8")
	c.Assert(err, check.IsNil)
	c1 := NewCIDR(ipnet)
	c.Assert(c1, check.Not(check.IsNil))

	c2 := c1.DeepCopy()
	c.Assert(c1, checker.DeepEquals, c2)
}

func (t *CidrTestSuite) TestNewCIDRNil(c *check.C) {
	c.Assert(NewCIDR(nil), check.IsNil)
}

func (t *CidrTestSuite) TestIllegalParseCIDR(c *check.C) {
	c1, err := ParseCIDR("Illegal")
	c.Assert(c1, check.IsNil)
	c.Assert(err, check.Not(check.IsNil))
}

func (t *CidrTestSuite) TestIllegalMustParseCIDR(c *check.C) {
	defer func() {
		if r := recover(); r == nil {
			c.Errorf("MustParseCIDR did not panic on illegal CIDR")
		}
	}()
	c1 := MustParseCIDR("Illegal")
	c.Assert(c1, check.IsNil)
}

func (t *CidrTestSuite) TestAvailableIPs(c *check.C) {
	cidr := MustParseCIDR("10.0.0.0/8")
	c.Assert(cidr.AvailableIPs(), check.Equals, 16777216)
	cidr = MustParseCIDR("1.1.1.1/32")
	c.Assert(cidr.AvailableIPs(), check.Equals, 1)
}

func (t *CidrTestSuite) TestEqual(c *check.C) {
	ipNet := &net.IPNet{
		IP:   net.ParseIP("1.2.3.4"),
		Mask: net.CIDRMask(1, 2),
	}

	type fields struct {
		n *CIDR
	}
	type args struct {
		o *CIDR
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "test-1",
			fields: fields{
				n: &CIDR{
					IPNet: &net.IPNet{
						IP:   nil,
						Mask: nil,
					},
				},
			},
			args: args{
				o: &CIDR{
					IPNet: &net.IPNet{
						IP:   nil,
						Mask: nil,
					},
				},
			},
			want: true,
		},
		{
			name:   "test-2",
			fields: fields{},
			args: args{
				o: &CIDR{
					IPNet: &net.IPNet{
						IP:   nil,
						Mask: nil,
					},
				},
			},
			want: false,
		},
		{
			name: "test-3",
			fields: fields{
				n: &CIDR{
					IPNet: &net.IPNet{
						IP:   nil,
						Mask: nil,
					},
				},
			},
			args: args{},
			want: false,
		},
		{
			name: "test-4",
			fields: fields{
				n: &CIDR{
					IPNet: &net.IPNet{
						IP:   net.ParseIP("1.2.3.4"),
						Mask: net.CIDRMask(1, 2),
					},
				},
			},
			args: args{
				o: &CIDR{
					IPNet: &net.IPNet{
						IP:   nil,
						Mask: nil,
					},
				},
			},
			want: false,
		},
		{
			name: "test-5",
			fields: fields{
				n: &CIDR{
					IPNet: &net.IPNet{
						IP:   net.ParseIP("1.2.3.4"),
						Mask: net.CIDRMask(1, 2),
					},
				},
			},
			args: args{
				o: &CIDR{
					IPNet: &net.IPNet{
						IP:   net.ParseIP("1.2.3.4"),
						Mask: net.CIDRMask(1, 2),
					},
				},
			},
			want: true,
		},
		{
			name: "test-6",
			fields: fields{
				n: &CIDR{
					IPNet: ipNet,
				},
			},
			args: args{
				o: &CIDR{
					IPNet: ipNet,
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		c.Assert(tt.fields.n.Equal(tt.args.o), check.Equals, tt.want, check.Commentf("Test Name: %s", tt.name))
	}
}

func mustNewCIDRs(cidrs ...string) []*net.IPNet {
	ipnets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		ipnets = append(ipnets, ipNet)
	}
	return ipnets
}

func (t *CidrTestSuite) TestRemoveAll(c *check.C) {
	type args struct {
		ipNets   []*net.IPNet
		toRemove []*net.IPNet
	}
	tests := []struct {
		name string
		args args
		want []*net.IPNet
	}{
		{
			name: "remove head",
			args: args{
				ipNets:   mustNewCIDRs("10.10.0.0/24", "10.10.1.0/24", "10.10.2.0/24"),
				toRemove: mustNewCIDRs("10.10.0.0/24"),
			},
			want: mustNewCIDRs("10.10.1.0/24", "10.10.2.0/24"),
		},
		{
			name: "remove middle",
			args: args{
				ipNets:   mustNewCIDRs("10.10.0.0/24", "10.10.1.0/24", "10.10.2.0/24"),
				toRemove: mustNewCIDRs("10.10.1.0/24"),
			},
			want: mustNewCIDRs("10.10.0.0/24", "10.10.2.0/24"),
		},
		{
			name: "remove tail",
			args: args{
				ipNets:   mustNewCIDRs("10.10.0.0/24", "10.10.1.0/24", "10.10.2.0/24"),
				toRemove: mustNewCIDRs("10.10.2.0/24"),
			},
			want: mustNewCIDRs("10.10.0.0/24", "10.10.1.0/24"),
		},
		{
			name: "remove all",
			args: args{
				ipNets:   mustNewCIDRs("10.10.0.0/24", "10.10.1.0/24", "10.10.2.0/24"),
				toRemove: mustNewCIDRs("10.10.0.0/24", "10.10.1.0/24", "10.10.2.0/24"),
			},
			want: []*net.IPNet{},
		},
		{
			name: "remove none",
			args: args{
				ipNets:   mustNewCIDRs("10.10.0.0/24", "10.10.1.0/24", "10.10.2.0/24"),
				toRemove: []*net.IPNet{},
			},
			want: mustNewCIDRs("10.10.0.0/24", "10.10.1.0/24", "10.10.2.0/24"),
		},
		{
			name: "remove duplicates",
			args: args{
				ipNets:   mustNewCIDRs("10.10.0.0/24", "10.10.1.0/24", "10.10.2.0/24", "10.10.3.0/24", "10.10.0.0/24"),
				toRemove: mustNewCIDRs("10.10.0.0/24", "10.10.2.0/24"),
			},
			want: mustNewCIDRs("10.10.1.0/24", "10.10.3.0/24"),
		},
		{
			name: "keep duplicates",
			args: args{
				ipNets:   mustNewCIDRs("10.10.0.0/24", "10.10.1.0/24", "10.10.2.0/24", "10.10.3.0/24", "10.10.0.0/24"),
				toRemove: mustNewCIDRs("10.10.1.0/24"),
			},
			want: mustNewCIDRs("10.10.0.0/24", "10.10.2.0/24", "10.10.3.0/24", "10.10.0.0/24"),
		},
		{
			name: "remove nil",
			args: args{
				ipNets:   mustNewCIDRs("10.10.0.0/24", "10.10.1.0/24", "10.10.2.0/24"),
				toRemove: nil,
			},
			want: mustNewCIDRs("10.10.0.0/24", "10.10.1.0/24", "10.10.2.0/24"),
		},
		{
			name: "remove from empty",
			args: args{
				ipNets:   []*net.IPNet{},
				toRemove: mustNewCIDRs("10.10.1.0/24"),
			},
			want: []*net.IPNet{},
		},
		{
			name: "remove from nil",
			args: args{
				ipNets:   nil,
				toRemove: mustNewCIDRs("10.10.1.0/24"),
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		result := RemoveAll(tt.args.ipNets, tt.args.toRemove)
		c.Assert(result, checker.DeepEquals, tt.want, check.Commentf("Test Name: %s", tt.name))
	}
}
