// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"k8s.io/utils/ptr"

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

func Test_desiredEnvoyHTTPRouteConfiguration_redirectScheme(t *testing.T) {
	redirectToHTTPS := model.HTTPRoute{
		PathMatch: model.StringMatch{Prefix: "/"},
		RequestRedirect: &model.HTTPRequestRedirectFilter{
			Scheme:     ptr.To("https"),
			StatusCode: ptr.To(302),
		},
	}

	res, err := (&cecTranslator{}).desiredEnvoyHTTPRouteConfiguration(&model.Model{
		HTTP: []model.HTTPListener{
			{
				Port:     80,
				Protocol: model.ListenerProtocolHTTP,
				Hostname: "example.com",
				Routes:   []model.HTTPRoute{redirectToHTTPS},
			},
			{
				Port:     443,
				Protocol: model.ListenerProtocolHTTPS,
				Hostname: "example.com",
				TLS:      []model.TLSSecret{{Name: "example-tls", Namespace: "default"}},
				Routes:   []model.HTTPRoute{redirectToHTTPS},
			},
		},
	})
	require.NoError(t, err)

	guarded := map[string]bool{}
	for _, raw := range res {
		rc := &envoy_config_route_v3.RouteConfiguration{}
		require.NoError(t, proto.Unmarshal(raw.Value, rc))
		require.Len(t, rc.GetVirtualHosts(), 1)
		require.Len(t, rc.GetVirtualHosts()[0].GetRoutes(), 1)
		guarded[rc.GetName()] = len(rc.GetVirtualHosts()[0].GetRoutes()[0].GetMatch().GetHeaders()) > 0
	}

	// The HTTP listener's redirect changes the scheme, so it keeps the loop guard.
	require.True(t, guarded["listener-insecure"])
	// The HTTPS listener is already https, so a guard would never match.
	require.False(t, guarded["listener-secure"])
}
