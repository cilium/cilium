// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewRouteConfiguration(t *testing.T) {
	res, err := NewRouteConfiguration("dummy-name", []*envoy_config_route_v3.VirtualHost{
		{
			Name: "dummy-virtual-host",
		},
	})
	require.Nil(t, err)

	routeConfiguration := &envoy_config_route_v3.RouteConfiguration{}
	err = proto.Unmarshal(res.Value, routeConfiguration)

	require.Nil(t, err)
	require.Equal(t, "dummy-name", routeConfiguration.GetName())
	require.Len(t, routeConfiguration.GetVirtualHosts(), 1)
	require.Equal(t, "dummy-virtual-host", routeConfiguration.GetVirtualHosts()[0].GetName())
}
