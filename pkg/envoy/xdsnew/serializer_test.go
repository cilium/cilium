package xdsnew

import (
	"testing"

	"github.com/cilium/cilium/pkg/envoy/xds"
	cilium "github.com/cilium/proxy/go/cilium/api"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/stretchr/testify/require"
)

func TestMarshalUnmarshalEmptyResources(t *testing.T) {
	require := require.New(t)

	resources := xds.Resources{
		Endpoints:       map[string]*endpoint.ClusterLoadAssignment{},
		Clusters:        map[string]*cluster.Cluster{},
		Routes:          map[string]*route.RouteConfiguration{},
		Listeners:       map[string]*listener.Listener{},
		Secrets:         map[string]*secret.Secret{},
		NetworkPolicies: map[string]*cilium.NetworkPolicy{},
	}

	encodedResources, err := Marshal(&resources)
	require.NoError(err)

	decodedResources, err := Unmarshal(encodedResources)
	require.NoError(err)

	require.Equal(resources, decodedResources)
}

func TestMarshalUnmarshalResources(t *testing.T) {
	require := require.New(t)

	resources := xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{
			"listener1": {
				Name: "listener1",
				Address: &envoy_config_core_v3.Address{
					Address: &envoy_config_core_v3.Address_SocketAddress{
						SocketAddress: &envoy_config_core_v3.SocketAddress{
							Protocol: envoy_config_core_v3.SocketAddress_TCP,
							Address:  "0.0.0.0",
							PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
								PortValue: 8080,
							},
						},
					},
				},
			},
		},
		Clusters: map[string]*envoy_config_cluster.Cluster{
			"cluster1": {
				Name: "cluster1",
			},
		},
		Secrets: map[string]*envoy_config_tls.Secret{
			"secret1": {
				Name: "secret1",
			},
		},
		Routes: map[string]*envoy_config_route.RouteConfiguration{
			"routeConfig1": {
				Name: "routeConfig1",
			},
		},
		Endpoints:       map[string]*envoy_config_endpoint.ClusterLoadAssignment{},
		NetworkPolicies: map[string]*cilium.NetworkPolicy{},
	}

	encodedResources, err := Marshal(&resources)
	require.NoError(err)

	decodedResources, err := Unmarshal(encodedResources)
	require.NoError(err)

	require.Equal(resources, decodedResources)
}
