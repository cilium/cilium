// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
