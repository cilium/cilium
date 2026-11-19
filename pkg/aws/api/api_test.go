// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"net/netip"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

type Filters []ec2_types.Filter

func (s Filters) Len() int           { return len(s) }
func (s Filters) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s Filters) Less(i, j int) bool { return strings.Compare(*s[i].Name, *s[j].Name) > 0 }

func TestNewSubnetsFilters(t *testing.T) {
	type args struct {
		tags map[string]string
		ids  []string
	}
	tests := []struct {
		name string
		args args
		want []ec2_types.Filter
	}{
		{
			name: "empty arguments",
			args: args{
				tags: map[string]string{},
				ids:  []string{},
			},
			want: []ec2_types.Filter{},
		},

		{
			name: "ids only",
			args: args{
				tags: map[string]string{},
				ids:  []string{"a", "b"},
			},
			want: []ec2_types.Filter{
				{
					Name:   aws.String("subnet-id"),
					Values: []string{"a", "b"},
				},
			},
		},

		{
			name: "tags only",
			args: args{
				tags: map[string]string{"a": "b", "c": "d"},
				ids:  []string{},
			},
			want: []ec2_types.Filter{
				{
					Name:   aws.String("tag:a"),
					Values: []string{"b"},
				},
				{
					Name:   aws.String("tag:c"),
					Values: []string{"d"},
				},
			},
		},

		{
			name: "tags and ids",
			args: args{
				tags: map[string]string{"a": "b"},
				ids:  []string{"c", "d"},
			},
			want: []ec2_types.Filter{
				{
					Name:   aws.String("tag:a"),
					Values: []string{"b"},
				},
				{
					Name:   aws.String("subnet-id"),
					Values: []string{"c", "d"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewSubnetsFilters(tt.args.tags, tt.args.ids)
			sort.Sort(Filters(got))
			sort.Sort(Filters(tt.want))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNewTagsFilters(t *testing.T) {
	type args struct {
		tags map[string]string
	}
	tests := []struct {
		name string
		args args
		want []ec2_types.Filter
	}{
		{
			name: "empty arguments",
			args: args{
				tags: map[string]string{},
			},
			want: []ec2_types.Filter{},
		},

		{
			name: "tags",
			args: args{
				tags: map[string]string{"a": "b", "c": "d"},
			},
			want: []ec2_types.Filter{
				{
					Name:   aws.String("tag:a"),
					Values: []string{"b"},
				},
				{
					Name:   aws.String("tag:c"),
					Values: []string{"d"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewTagsFilter(tt.args.tags)
			sort.Sort(Filters(got))
			sort.Sort(Filters(tt.want))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseENIPublicIP(t *testing.T) {
	newIface := func(assoc *ec2_types.NetworkInterfaceAssociation) *ec2_types.NetworkInterface {
		return &ec2_types.NetworkInterface{
			PrivateIpAddress: aws.String("10.0.0.1"),
			Association:      assoc,
		}
	}

	tests := []struct {
		name           string
		assoc          *ec2_types.NetworkInterfaceAssociation
		wantPublicIP   string
		wantValidPubIP bool
	}{
		{
			name:           "no association",
			assoc:          nil,
			wantValidPubIP: false,
		},
		{
			name:           "association without a public IP (nil pointer)",
			assoc:          &ec2_types.NetworkInterfaceAssociation{},
			wantValidPubIP: false,
		},
		{
			name:           "association with an empty public IP",
			assoc:          &ec2_types.NetworkInterfaceAssociation{PublicIp: aws.String("")},
			wantValidPubIP: false,
		},
		{
			name:           "association with a valid public IP",
			assoc:          &ec2_types.NetworkInterfaceAssociation{PublicIp: aws.String("203.0.113.1")},
			wantPublicIP:   "203.0.113.1",
			wantValidPubIP: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, eni, err := parseENI(newIface(tt.assoc), nil, nil)
			require.NoError(t, err)
			require.NotNil(t, eni)
			assert.Equal(t, tt.wantValidPubIP, eni.PublicIP.IsValid())
			if tt.wantValidPubIP {
				assert.Equal(t, tt.wantPublicIP, eni.PublicIP.String())
			}
		})
	}
}

func TestParseENIIPv4Prefixes(t *testing.T) {
	iface := &ec2_types.NetworkInterface{
		PrivateIpAddress: aws.String("10.0.0.1"),
		PrivateIpAddresses: []ec2_types.NetworkInterfacePrivateIpAddress{
			{PrivateIpAddress: aws.String("10.0.0.1"), Primary: aws.Bool(true)},
			{PrivateIpAddress: aws.String("10.0.0.2")},
		},
		Ipv4Prefixes: []ec2_types.Ipv4PrefixSpecification{
			{Ipv4Prefix: aws.String("10.0.1.0/28")},
		},
	}

	_, eni, err := parseENI(iface, nil, nil)
	require.NoError(t, err)

	// Delegated prefixes are reported as-is and are not expanded into
	// individual addresses.
	require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.1.0/28"))}, eni.Prefixes)
	require.Equal(t, []iputil.Addr{
		iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
		iputil.AddrFrom(netip.MustParseAddr("10.0.0.2")),
	}, eni.Addresses)
}

func TestParseENIIPv6(t *testing.T) {
	// addr describes one entry of the ENI's assigned IPv6 addresses.
	type addr struct {
		ip      string
		primary bool
	}

	newIface := func(addrs []addr, prefixes []string) *ec2_types.NetworkInterface {
		iface := &ec2_types.NetworkInterface{
			PrivateIpAddress: aws.String("10.0.0.1"),
		}
		for _, a := range addrs {
			iface.Ipv6Addresses = append(iface.Ipv6Addresses, ec2_types.NetworkInterfaceIpv6Address{
				Ipv6Address:   aws.String(a.ip),
				IsPrimaryIpv6: aws.Bool(a.primary),
			})
		}
		for _, p := range prefixes {
			iface.Ipv6Prefixes = append(iface.Ipv6Prefixes, ec2_types.Ipv6PrefixSpecification{
				Ipv6Prefix: aws.String(p),
			})
		}
		return iface
	}

	tests := []struct {
		name      string
		addrs     []addr
		prefixes  []string
		want      string
		wantError bool
	}{
		{
			name: "no IPv6 address or prefix leaves the ENI without an IPv6 address",
		},
		{
			name:     "address is taken out of the delegated prefix",
			prefixes: []string{"2001:db8:0:1::/80"},
			want:     "2001:db8:0:1:0:ffff:ffff:ffff",
		},
		{
			name:     "address is taken out of the lowest delegated prefix",
			prefixes: []string{"2001:db8:0:1:0:1::/80", "2001:db8:0:1::/80"},
			want:     "2001:db8:0:1:0:ffff:ffff:ffff",
		},
		{
			name:  "the only assigned address is used",
			addrs: []addr{{ip: "2001:db8:0:2::5"}},
			want:  "2001:db8:0:2::5",
		},
		{
			name:  "the primary address wins over the other assigned ones",
			addrs: []addr{{ip: "2001:db8:0:2::5"}, {ip: "2001:db8:0:2::9", primary: true}},
			want:  "2001:db8:0:2::9",
		},
		{
			name:  "the lowest address is picked when none is primary",
			addrs: []addr{{ip: "2001:db8:0:2::9"}, {ip: "2001:db8:0:2::5"}, {ip: "2001:db8:0:2::7"}},
			want:  "2001:db8:0:2::5",
		},
		{
			name:     "an assigned address outside the delegated prefix wins over the prefix",
			addrs:    []addr{{ip: "2001:db8:0:2::5", primary: true}},
			prefixes: []string{"2001:db8:0:1::/80"},
			want:     "2001:db8:0:2::5",
		},
		{
			name:      "a malformed assigned address is an error",
			addrs:     []addr{{ip: "not-an-ip"}},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, eni, err := parseENI(newIface(tt.addrs, tt.prefixes), nil, nil)
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, eni)

			if tt.want == "" {
				assert.False(t, eni.IPv6.IsValid())
				return
			}
			assert.Equal(t, tt.want, eni.IPv6.String())
		})
	}
}

func TestParseVPCIPv6CIDRs(t *testing.T) {
	type assoc struct {
		cidr  *string
		state *ec2_types.VpcCidrBlockStateCode
	}
	associated := ec2_types.VpcCidrBlockStateCodeAssociated
	associating := ec2_types.VpcCidrBlockStateCodeAssociating
	disassociated := ec2_types.VpcCidrBlockStateCodeDisassociated

	newVPC := func(assocs []assoc) ec2_types.Vpc {
		v := ec2_types.Vpc{VpcId: aws.String("vpc-1")}
		for i, a := range assocs {
			entry := ec2_types.VpcIpv6CidrBlockAssociation{
				AssociationId: aws.String("vpc-cidr-assoc-" + string(rune('a'+i))),
				Ipv6CidrBlock: a.cidr,
			}
			if a.state != nil {
				entry.Ipv6CidrBlockState = &ec2_types.VpcCidrBlockState{State: *a.state}
			}
			v.Ipv6CidrBlockAssociationSet = append(v.Ipv6CidrBlockAssociationSet, entry)
		}
		return v
	}

	tests := []struct {
		name      string
		assocs    []assoc
		want      []string
		wantError bool
	}{
		{
			name: "no association",
		},
		{
			name: "multiple active associations are masked, deduplicated and sorted",
			assocs: []assoc{
				{cidr: aws.String("2600:1f14:abcd:ef00::/56"), state: &associated},
				{cidr: aws.String("2600:1f14:1111:2200::1/56"), state: &associated},
				{cidr: aws.String("2600:1f14:abcd:ef00::/56"), state: &associated},
				{cidr: aws.String("2600:1f14:1111:2200::/64"), state: &associated},
			},
			want: []string{"2600:1f14:1111:2200::/56", "2600:1f14:1111:2200::/64", "2600:1f14:abcd:ef00::/56"},
		},
		{
			name: "associations without state or not associated are skipped",
			assocs: []assoc{
				{cidr: aws.String("2600:1f14:abcd:ef00::/56"), state: &associated},
				{cidr: aws.String("2600:1f14:1111:2200::/56")},
				{cidr: aws.String("2600:1f14:2222:3300::/56"), state: &associating},
				{cidr: aws.String("2600:1f14:3333:4400::/56"), state: &disassociated},
				// Skipped entries are not validated.
				{cidr: aws.String("not-a-cidr"), state: &disassociated},
			},
			want: []string{"2600:1f14:abcd:ef00::/56"},
		},
		{
			name: "a nil CIDR is an error",
			assocs: []assoc{
				{cidr: aws.String("2600:1f14:abcd:ef00::/56"), state: &associated},
				{state: &associated},
			},
			wantError: true,
		},
		{
			name: "an empty CIDR is an error",
			assocs: []assoc{
				{cidr: aws.String("2600:1f14:abcd:ef00::/56"), state: &associated},
				{cidr: aws.String(""), state: &associated},
			},
			wantError: true,
		},
		{
			name: "a malformed CIDR is an error",
			assocs: []assoc{
				{cidr: aws.String("2600:1f14:abcd:ef00::/56"), state: &associated},
				{cidr: aws.String("2600:1f14::/129"), state: &associated},
			},
			wantError: true,
		},
		{
			name: "an IPv4 CIDR is an error",
			assocs: []assoc{
				{cidr: aws.String("2600:1f14:abcd:ef00::/56"), state: &associated},
				{cidr: aws.String("10.0.0.0/16"), state: &associated},
			},
			wantError: true,
		},
		{
			name: "an IPv4-mapped CIDR is an error",
			assocs: []assoc{
				{cidr: aws.String("2600:1f14:abcd:ef00::/56"), state: &associated},
				{cidr: aws.String("::ffff:10.0.0.0/112"), state: &associated},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseVPCIPv6CIDRs(newVPC(tt.assocs))
			if tt.wantError {
				require.Error(t, err)
				require.Contains(t, err.Error(), "vpc-cidr-assoc-b")
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)

			var want []iputil.Prefix
			for _, s := range tt.want {
				want = append(want, iputil.PrefixFrom(netip.MustParsePrefix(s)))
			}
			require.Equal(t, want, got)
		})
	}
}

func TestParseENIVPCIPv6CIDRs(t *testing.T) {
	vpcs := ipamTypes.VirtualNetworkMap{
		"vpc-1": {
			ID:          "vpc-1",
			PrimaryCIDR: iputil.PrefixFrom(netip.MustParsePrefix("192.168.0.0/16")),
			IPv6CIDRs: []iputil.Prefix{
				iputil.PrefixFrom(netip.MustParsePrefix("2600:1f14:1111:2200::/56")),
				iputil.PrefixFrom(netip.MustParsePrefix("2600:1f14:abcd:ef00::/56")),
			},
		},
	}
	iface := &ec2_types.NetworkInterface{
		PrivateIpAddress: aws.String("192.168.1.1"),
		VpcId:            aws.String("vpc-1"),
	}

	_, eni, err := parseENI(iface, vpcs, nil)
	require.NoError(t, err)
	require.Equal(t, []iputil.Prefix{
		iputil.PrefixFrom(netip.MustParsePrefix("2600:1f14:1111:2200::/56")),
		iputil.PrefixFrom(netip.MustParsePrefix("2600:1f14:abcd:ef00::/56")),
	}, eni.VPC.IPv6CIDRs)

	// The ENI status must not alias the shared VPC inventory.
	vpcs["vpc-1"].IPv6CIDRs[0] = iputil.PrefixFrom(netip.MustParsePrefix("2001:db8::/56"))
	require.Equal(t, iputil.PrefixFrom(netip.MustParsePrefix("2600:1f14:1111:2200::/56")), eni.VPC.IPv6CIDRs[0])
}
