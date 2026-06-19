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
			_, eni, err := parseENI(newIface(tt.assoc), nil, nil, false)
			require.NoError(t, err)
			require.NotNil(t, eni)
			assert.Equal(t, tt.wantValidPubIP, eni.PublicIP.IsValid())
			if tt.wantValidPubIP {
				assert.Equal(t, tt.wantPublicIP, eni.PublicIP.String())
			}
		})
	}
}
