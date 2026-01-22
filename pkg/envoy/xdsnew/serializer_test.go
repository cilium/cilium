package xdsnew

import (
	"testing"

	"github.com/cilium/cilium/pkg/envoy/xds"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"

	"github.com/stretchr/testify/require"
)

func TestMarshalUnmarshal(t *testing.T) {
	require := require.New(t)

	resources := xds.Resources{
		Endpoints: []*envoy_config_endpoint.ClusterLoadAssignment{{}},
		Clusters:  []*envoy_config_cluster.Cluster{{}},
		Routes:    []*envoy_config_route.RouteConfiguration{{}},
		Listeners: []*envoy_config_listener.Listener{{}},
		Secrets:   []*envoy_config_tls.Secret{{}},
	}

	encodedResources, err := Marshal(resources)
	require.NoError(err)

	decodedResources, err := Unmarshal(encodedResources)
	require.NoError(err)

	require.Equal(resources, decodedResources)
}
