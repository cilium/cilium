// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	metricsmock "github.com/cilium/cilium/pkg/api/metrics/mock"
)

func TestAssignPrivateIpAddressesReturnsOnlyAssignedAddresses(t *testing.T) {
	ec2Client := ec2.New(ec2.Options{
		Region:      "us-east-1",
		Credentials: aws.AnonymousCredentials{},
		HTTPClient: smithyhttp.ClientDoFunc(func(req *http.Request) (*http.Response, error) {
			require.NoError(t, req.ParseForm())
			require.Equal(t, "AssignPrivateIpAddresses", req.Form.Get("Action"))
			require.Equal(t, "eni-123", req.Form.Get("NetworkInterfaceId"))
			require.Equal(t, "2", req.Form.Get("SecondaryPrivateIpAddressCount"))

			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": {"text/xml"}},
				Body: io.NopCloser(strings.NewReader(`<AssignPrivateIpAddressesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
	<networkInterfaceId>eni-123</networkInterfaceId>
	<assignedPrivateIpAddressesSet>
		<item><privateIpAddress>10.0.0.2</privateIpAddress></item>
	</assignedPrivateIpAddressesSet>
</AssignPrivateIpAddressesResponse>`)),
			}, nil
		}),
	})
	client := NewClient(hivetest.Logger(t), ec2Client, metricsmock.NewMockMetrics(), 10, 1, nil, nil, nil, 0)

	assignedIPs, err := client.AssignPrivateIpAddresses(t.Context(), "eni-123", 2)
	require.NoError(t, err)
	require.Equal(t, []string{"10.0.0.2"}, assignedIPs)
}

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
