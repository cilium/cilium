// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func Test_routeConfiguration(t *testing.T) {
	res, err := routeConfiguration("dummy-name", []*envoy_config_route_v3.VirtualHost{
		{
			Name: "dummy-virtual-host",
		},
	})
	require.NoError(t, err)

	routeConfiguration := &envoy_config_route_v3.RouteConfiguration{}
	err = proto.Unmarshal(res.Value, routeConfiguration)

	require.NoError(t, err)
	require.Equal(t, "dummy-name", routeConfiguration.GetName())
	require.Len(t, routeConfiguration.GetVirtualHosts(), 1)
	require.Equal(t, "dummy-virtual-host", routeConfiguration.GetVirtualHosts()[0].GetName())
}
