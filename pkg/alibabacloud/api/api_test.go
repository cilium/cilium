// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/alibabacloud/types"
	metricsmock "github.com/cilium/cilium/pkg/api/metrics/mock"
	iputil "github.com/cilium/cilium/pkg/ip"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newTestClient(t *testing.T, handler func(*http.Request) (int, string)) *Client {
	t.Helper()
	client, err := ecs.NewClientWithAccessKey("cn-hangzhou", "test-access-key", "test-secret")
	require.NoError(t, err)
	client.SetTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		status, body := handler(req)
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	}))
	return NewClient(hivetest.Logger(t), nil, client, metricsmock.NewMockMetrics(), 100, 10, nil)
}

func TestCreateNetworkInterfaceIPv6(t *testing.T) {
	for _, tt := range []struct {
		name             string
		secondaryIPCount int
		allocateIPv6     bool
	}{
		{name: "IPv4 primary only"},
		{name: "IPv4 secondary addresses", secondaryIPCount: 2},
		{name: "dual stack primary only", allocateIPv6: true},
		{name: "dual stack secondary addresses", secondaryIPCount: 2, allocateIPv6: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestClient(t, func(req *http.Request) (int, string) {
				require.NoError(t, req.ParseForm())
				require.Equal(t, CreateNetworkInterface, req.Form.Get("Action"))
				require.Equal(t, "vsw-1", req.Form.Get("VSwitchId"))
				require.Equal(t, "sg-1", req.Form.Get("SecurityGroupIds.1"))
				require.Equal(t, "owner", req.Form.Get("Tag.1.Key"))
				require.Equal(t, "cilium", req.Form.Get("Tag.1.Value"))
				if tt.secondaryIPCount > 0 {
					require.Equal(t, fmt.Sprint(tt.secondaryIPCount), req.Form.Get("SecondaryPrivateIpAddressCount"))
				} else {
					require.NotContains(t, req.Form, "SecondaryPrivateIpAddressCount")
				}
				require.NotContains(t, req.Form, "Ipv6AddressCount")
				prefixes := ""
				if tt.allocateIPv6 {
					require.Equal(t, "1", req.Form.Get("Ipv6PrefixCount"))
					prefixes = `,"Ipv6PrefixSets":{"Ipv6PrefixSet":[{"Ipv6Prefix":"2001:db8:1:2:3::/80"}]}`
				} else {
					require.NotContains(t, req.Form, "Ipv6PrefixCount")
				}
				return http.StatusOK, `{"NetworkInterfaceId":"eni-1","PrivateIpAddress":"10.0.0.1","PrivateIpSets":{"PrivateIpSet":[{"PrivateIpAddress":"10.0.0.1","Primary":true}]}` + prefixes + `}`
			})

			id, eni, err := client.CreateNetworkInterface(t.Context(), tt.secondaryIPCount, "vsw-1", []string{"sg-1"}, map[string]string{"owner": "cilium"}, tt.allocateIPv6)
			require.NoError(t, err)
			require.Equal(t, "eni-1", id)
			require.Equal(t, "10.0.0.1", eni.PrimaryIPAddress.String())
			require.Len(t, eni.PrivateIPSets, 1)
			if tt.allocateIPv6 {
				require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("2001:db8:1:2:3::/80"))}, eni.IPv6Prefixes)
			} else {
				require.Empty(t, eni.IPv6Prefixes)
			}
		})
	}
}

func TestAssignENIIPv6Prefix(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client := newTestClient(t, func(req *http.Request) (int, string) {
				require.NoError(t, req.ParseForm())
				require.Equal(t, AssignIPv6Addresses, req.Form.Get("Action"))
				require.Equal(t, "eni-1", req.Form.Get("NetworkInterfaceId"))
				require.Equal(t, "1", req.Form.Get("Ipv6PrefixCount"))
				require.NotContains(t, req.Form, "Ipv6AddressCount")
				if status == http.StatusForbidden {
					return status, `{"Code":"Forbidden","Message":"Permission denied","RequestId":"request-1"}`
				}
				return status, `{"NetworkInterfaceId":"eni-1","Ipv6PrefixSets":{"Ipv6Prefix":["2001:db8:1:2:3::/80"]}}`
			})

			err := client.AssignENIIPv6Prefix(t.Context(), "eni-1")
			if status == http.StatusOK {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "Forbidden")
			}
		})
	}
}

func TestGetInstanceIPv6Prefixes(t *testing.T) {
	client := newTestClient(t, func(req *http.Request) (int, string) {
		require.NoError(t, req.ParseForm())
		require.Equal(t, DescribeNetworkInterfaces, req.Form.Get("Action"))
		require.Equal(t, "i-1", req.Form.Get("InstanceId"))
		return http.StatusOK, `{"PageNumber":1,"PageSize":1000,"TotalCount":1,"NetworkInterfaceSets":{"NetworkInterfaceSet":[{
			"NetworkInterfaceId":"eni-1","InstanceId":"i-1","PrivateIpAddress":"10.0.0.1",
			"Ipv6PrefixSets":{"Ipv6PrefixSet":[
				{"Ipv6Prefix":"2001:db8:1:2:3::/80"},
				{"Ipv6Prefix":"invalid"},
				{"Ipv6Prefix":"2001:db8:1:2:4::/80"}
			]}
		}]}}`
	})

	instance, err := client.GetInstance(t.Context(), nil, nil, "i-1")
	require.NoError(t, err)
	eni := instance.Interfaces["eni-1"].(*types.ENI)
	require.Equal(t, "10.0.0.1", eni.PrimaryIPAddress.String())
	require.Equal(t, []iputil.Prefix{
		iputil.PrefixFrom(netip.MustParsePrefix("2001:db8:1:2:3::/80")),
		iputil.PrefixFrom(netip.MustParsePrefix("2001:db8:1:2:4::/80")),
	}, eni.IPv6Prefixes)
}
