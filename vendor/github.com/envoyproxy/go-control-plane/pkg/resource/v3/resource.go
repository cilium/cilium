package resource

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
)

// Type is an alias to string which we expose to users of the snapshot API which accepts `resource.Type` resource URLs.
type Type = string

// Resource types in xDS v3.
const (
	APITypePrefix       = "type.googleapis.com/"
	EndpointType        = APITypePrefix + "envoy.config.endpoint.v3.ClusterLoadAssignment"
	ClusterType         = APITypePrefix + "envoy.config.cluster.v3.Cluster"
	RouteType           = APITypePrefix + "envoy.config.route.v3.RouteConfiguration"
	ScopedRouteType     = APITypePrefix + "envoy.config.route.v3.ScopedRouteConfiguration"
	VirtualHostType     = APITypePrefix + "envoy.config.route.v3.VirtualHost"
	ListenerType        = APITypePrefix + "envoy.config.listener.v3.Listener"
	SecretType          = APITypePrefix + "envoy.extensions.transport_sockets.tls.v3.Secret"
	ExtensionConfigType = APITypePrefix + "envoy.config.core.v3.TypedExtensionConfig"
	RuntimeType         = APITypePrefix + "envoy.service.runtime.v3.Runtime"
	ThriftRouteType     = APITypePrefix + "envoy.extensions.filters.network.thrift_proxy.v3.RouteConfiguration"

	// Rate Limit service
	RateLimitConfigType = APITypePrefix + "ratelimit.config.ratelimit.v3.RateLimitConfig"

	// AnyType is used only by ADS
	AnyType = ""
)

// Fetch urls in xDS v3.
const (
	FetchEndpoints        = "/v3/discovery:endpoints"
	FetchClusters         = "/v3/discovery:clusters"
	FetchListeners        = "/v3/discovery:listeners"
	FetchRoutes           = "/v3/discovery:routes"
	FetchScopedRoutes     = "/v3/discovery:scoped-routes"
	FetchSecrets          = "/v3/discovery:secrets" //nolint:gosec
	FetchRuntimes         = "/v3/discovery:runtime"
	FetchExtensionConfigs = "/v3/discovery:extension_configs"
)

// DefaultAPIVersion is the api version
const DefaultAPIVersion = core.ApiVersion_V3

// GetHTTPConnectionManager creates a HttpConnectionManager
// from filter. Returns nil if the filter doesn't have a valid
// HttpConnectionManager configuration.
func GetHTTPConnectionManager(filter *listener.Filter) *hcm.HttpConnectionManager {
	if typedConfig := filter.GetTypedConfig(); typedConfig != nil {
		config := &hcm.HttpConnectionManager{}
		if err := anypb.UnmarshalTo(typedConfig, config, proto.UnmarshalOptions{}); err == nil {
			return config
		}
	}

	return nil
}
