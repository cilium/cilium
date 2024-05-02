// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cidr

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNilDeepCopy(t *testing.T) {
	var c1 *CIDR
	require.Nil(t, c1.DeepCopy())
}

func TestDeepCopy(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("1.1.1.1/8")
	require.Nil(t, err)
	c1 := NewCIDR(ipnet)
	require.NotNil(t, c1)

	c2 := c1.DeepCopy()
	require.EqualValues(t, c2, c1)
}

func TestNewCIDRNil(t *testing.T) {
	require.Nil(t, NewCIDR(nil))
}

func TestIllegalParseCIDR(t *testing.T) {
	c1, err := ParseCIDR("Illegal")
	require.Nil(t, c1)
	require.NotNil(t, err)
}

func TestIllegalMustParseCIDR(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("MustParseCIDR did not panic on illegal CIDR")
		}
	}()
	c1 := MustParseCIDR("Illegal")
	require.Nil(t, c1)
}

func TestAvailableIPs(t *testing.T) {
	cidr := MustParseCIDR("10.0.0.0/8")
	require.Equal(t, 16777216, cidr.AvailableIPs())
	cidr = MustParseCIDR("1.1.1.1/32")
	require.Equal(t, 1, cidr.AvailableIPs())
}

func TestEqual(t *testing.T) {
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
		require.Equalf(t, tt.want, tt.fields.n.Equal(tt.args.o), "Test Name: %s", tt.name)
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

func TestRemoveAll(t *testing.T) {
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
		require.EqualValuesf(t, tt.want, result, "Test Name: %s", tt.name)
	}
}
