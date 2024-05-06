// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ec2

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
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
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSubnetsFilters() = %v, want %v", got, tt.want)
			}
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
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewTagsFilter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseEniIpAddresses(t *testing.T) {
	testCases := map[string]struct {
		iface             ec2_types.NetworkInterface
		usePrimary        bool
		wantIPv4Addresses []string
		wantIPv6Addresses []string
		wantErr           bool
	}{
		"IPv4 only ENI": {
			iface: ec2_types.NetworkInterface{
				NetworkInterfaceId: aws.String("eni-ipv4only"),
				PrivateIpAddress:   aws.String("192.0.2.1"),
				PrivateIpAddresses: []ec2_types.NetworkInterfacePrivateIpAddress{
					{
						Primary:          aws.Bool(true),
						PrivateIpAddress: aws.String("192.0.2.1"),
					},
					{
						Primary:          aws.Bool(false),
						PrivateIpAddress: aws.String("192.0.2.2"),
					},
					{
						Primary:          aws.Bool(false),
						PrivateIpAddress: aws.String("192.0.2.3"),
					},
				},
				Ipv6Address: nil,
				MacAddress:  aws.String("01:23:45:67:89:ab"),
			},
			usePrimary:        false,
			wantIPv4Addresses: []string{"192.0.2.2", "192.0.2.3"},
			wantErr:           false,
		},
		"IPv6 only ENI": {
			iface: ec2_types.NetworkInterface{
				NetworkInterfaceId: aws.String("eni-ipv6only"),
				PrivateIpAddress:   nil,
				Ipv6Address:        aws.String("2001:db8::1"),
				MacAddress:         aws.String("01:23:45:67:89:cd"),
				Ipv6Prefixes: []ec2_types.Ipv6PrefixSpecification{
					{
						Ipv6Prefix: aws.String("2001:db9::/80"),
					},
				},
			},
			usePrimary: false,
			wantIPv6Addresses: []string{"2001:db9::", "2001:db9::1", "2001:db9::2", "2001:db9::3", "2001:db9::4",
				"2001:db9::5", "2001:db9::6", "2001:db9::7", "2001:db9::8", "2001:db9::9", "2001:db9::a", "2001:db9::b",
				"2001:db9::c", "2001:db9::d", "2001:db9::e", "2001:db9::f", "2001:db9::10", "2001:db9::11", "2001:db9::12",
				"2001:db9::13", "2001:db9::14", "2001:db9::15", "2001:db9::16", "2001:db9::17", "2001:db9::18", "2001:db9::19",
				"2001:db9::1a", "2001:db9::1b", "2001:db9::1c", "2001:db9::1d", "2001:db9::1e", "2001:db9::1f", "2001:db9::20",
				"2001:db9::21", "2001:db9::22", "2001:db9::23", "2001:db9::24", "2001:db9::25", "2001:db9::26", "2001:db9::27",
				"2001:db9::28", "2001:db9::29", "2001:db9::2a", "2001:db9::2b", "2001:db9::2c", "2001:db9::2d", "2001:db9::2e",
				"2001:db9::2f", "2001:db9::30", "2001:db9::31", "2001:db9::32", "2001:db9::33", "2001:db9::34", "2001:db9::35",
				"2001:db9::36", "2001:db9::37", "2001:db9::38", "2001:db9::39", "2001:db9::3a", "2001:db9::3b", "2001:db9::3c",
				"2001:db9::3d", "2001:db9::3e", "2001:db9::3f"},
			wantErr: false,
		},
		"Dual-Stack ENI": {
			iface: ec2_types.NetworkInterface{
				NetworkInterfaceId: aws.String("eni-dualstack"),
				PrivateIpAddress:   aws.String("192.0.2.2"),
				PrivateIpAddresses: []ec2_types.NetworkInterfacePrivateIpAddress{
					{
						Primary:          aws.Bool(true),
						PrivateIpAddress: aws.String("192.0.2.1"),
					},
					{
						Primary:          aws.Bool(false),
						PrivateIpAddress: aws.String("192.0.2.2"),
					},
					{
						Primary:          aws.Bool(false),
						PrivateIpAddress: aws.String("192.0.2.3"),
					},
				},
				Ipv6Address: aws.String("2001:db8::2"),
				Ipv6Prefixes: []ec2_types.Ipv6PrefixSpecification{
					{
						Ipv6Prefix: aws.String("2001:db9::/80"),
					},
				},
				MacAddress: aws.String("01:23:45:67:89:ef"),
			},
			usePrimary:        false,
			wantIPv4Addresses: []string{"192.0.2.2", "192.0.2.3"},
			wantIPv6Addresses: []string{"2001:db9::", "2001:db9::1", "2001:db9::2", "2001:db9::3", "2001:db9::4",
				"2001:db9::5", "2001:db9::6", "2001:db9::7", "2001:db9::8", "2001:db9::9", "2001:db9::a", "2001:db9::b",
				"2001:db9::c", "2001:db9::d", "2001:db9::e", "2001:db9::f", "2001:db9::10", "2001:db9::11", "2001:db9::12",
				"2001:db9::13", "2001:db9::14", "2001:db9::15", "2001:db9::16", "2001:db9::17", "2001:db9::18", "2001:db9::19",
				"2001:db9::1a", "2001:db9::1b", "2001:db9::1c", "2001:db9::1d", "2001:db9::1e", "2001:db9::1f", "2001:db9::20",
				"2001:db9::21", "2001:db9::22", "2001:db9::23", "2001:db9::24", "2001:db9::25", "2001:db9::26", "2001:db9::27",
				"2001:db9::28", "2001:db9::29", "2001:db9::2a", "2001:db9::2b", "2001:db9::2c", "2001:db9::2d", "2001:db9::2e",
				"2001:db9::2f", "2001:db9::30", "2001:db9::31", "2001:db9::32", "2001:db9::33", "2001:db9::34", "2001:db9::35",
				"2001:db9::36", "2001:db9::37", "2001:db9::38", "2001:db9::39", "2001:db9::3a", "2001:db9::3b", "2001:db9::3c",
				"2001:db9::3d", "2001:db9::3e", "2001:db9::3f"},
			wantErr: false,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			_, eni, err := parseENI(&tc.iface, nil, nil, tc.usePrimary)

			if (err != nil) != tc.wantErr {
				t.Fatalf("parseENI() error = %v, wantErr %v", err, tc.wantErr)
			}

			if !slicesEqual(eni.Addresses, tc.wantIPv4Addresses) {
				t.Errorf("IPv4 addresses mismatch: got %v, want %v", eni.Addresses, tc.wantIPv4Addresses)
			}

			if !slicesEqual(eni.IPv6Addresses, tc.wantIPv6Addresses) {
				t.Errorf("IPv6 addresses mismatch: got %v, want %v", eni.IPv6Addresses, tc.wantIPv6Addresses)
			}
		})
	}
}

// slicesEqual checks if two slices of strings are equal (order does not matter).
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aMap := make(map[string]int)
	for _, item := range a {
		aMap[item]++
	}
	for _, item := range b {
		if _, ok := aMap[item]; !ok {
			return false
		}
		aMap[item]--
		if aMap[item] == 0 {
			delete(aMap, item)
		}
	}
	return len(aMap) == 0
}
