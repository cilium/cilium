// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/operator/pkg/model"
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

// HTTP listeners share one route configuration: a single listener off port 80 means a virtual
// host can be reached on that port too.
func Test_servesDefaultPortOnly(t *testing.T) {
	tls := []model.TLSSecret{{Name: "cert", Namespace: "default"}}
	m := &model.Model{HTTP: []model.HTTPListener{{Port: 80}, {Port: 443, TLS: tls}}}
	require.True(t, servesDefaultPortOnly(m, insecureHost))
	require.True(t, servesDefaultPortOnly(m, routeConfigKey(m, m.HTTP[1])))

	m = &model.Model{HTTP: []model.HTTPListener{{Port: 80}, {Port: 8080}, {Port: 8443, TLS: tls}}}
	require.False(t, servesDefaultPortOnly(m, insecureHost))
	require.False(t, servesDefaultPortOnly(m, routeConfigKey(m, m.HTTP[2])))
}
