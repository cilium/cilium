// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	envoy_config_cluster_v3 "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_upstreams_http_v3 "github.com/cilium/proxy/go/envoy/extensions/upstreams/http/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

const (
	httpProtocolOptionsType = "envoy.extensions.upstreams.http.v3.HttpProtocolOptions"
)

type HTTPVersionType int

const (
	HTTPVersionDownstream HTTPVersionType = -1
	HTTPVersionAuto       HTTPVersionType = 0
	HTTPVersion1          HTTPVersionType = 1
	HTTPVersion2          HTTPVersionType = 2
	HTTPVersion3          HTTPVersionType = 3
)

type ClusterMutator func(*envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster

// WithClusterLbPolicy sets the cluster's load balancing policy.
// https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers
func WithClusterLbPolicy(lbPolicy int32) ClusterMutator {
	return func(cluster *envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster {
		if cluster == nil {
			return cluster
		}
		cluster.LbPolicy = envoy_config_cluster_v3.Cluster_LbPolicy(lbPolicy)
		return cluster
	}
}

// WithOutlierDetection enables outlier detection on the cluster.
func WithOutlierDetection(splitExternalLocalOriginErrors bool) ClusterMutator {
	return func(cluster *envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster {
		if cluster == nil {
			return cluster
		}
		cluster.OutlierDetection = &envoy_config_cluster_v3.OutlierDetection{
			SplitExternalLocalOriginErrors: splitExternalLocalOriginErrors,
		}
		return cluster
	}
}

// WithConnectionTimeout sets the cluster's connection timeout.
func WithConnectionTimeout(seconds int) ClusterMutator {
	return func(cluster *envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster {
		if cluster == nil {
			return cluster
		}
		cluster.ConnectTimeout = &durationpb.Duration{Seconds: int64(seconds)}
		return cluster
	}
}

// WithIdleTimeout sets the cluster's connection idle timeout.
func WithIdleTimeout(seconds int) ClusterMutator {
	return func(cluster *envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster {
		if cluster == nil {
			return cluster
		}
		a := cluster.TypedExtensionProtocolOptions[httpProtocolOptionsType]
		opts := &envoy_upstreams_http_v3.HttpProtocolOptions{}
		if err := a.UnmarshalTo(opts); err != nil {
			return cluster
		}
		opts.CommonHttpProtocolOptions = &envoy_config_core_v3.HttpProtocolOptions{
			IdleTimeout: &durationpb.Duration{Seconds: int64(seconds)},
		}
		cluster.TypedExtensionProtocolOptions[httpProtocolOptionsType] = toAny(opts)
		return cluster
	}
}

func WithProtocol(protocolVersion HTTPVersionType) ClusterMutator {
	return func(cluster *envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster {
		options := &envoy_upstreams_http_v3.HttpProtocolOptions{}
		switch protocolVersion {
		// Default protocol version in Envoy is HTTP1.1.
		case HTTPVersion1, HTTPVersionAuto:
			options.UpstreamProtocolOptions = &envoy_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_HttpProtocolOptions{},
				},
			}
		case HTTPVersion2:
			options.UpstreamProtocolOptions = &envoy_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{},
				},
			}
		case HTTPVersion3:
			options.UpstreamProtocolOptions = &envoy_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_Http3ProtocolOptions{},
				},
			}
		}

		cluster.TypedExtensionProtocolOptions = map[string]*anypb.Any{
			httpProtocolOptionsType: toAny(options),
		}
		return cluster
	}
}

// NewHTTPCluster creates a new Envoy cluster.
func NewHTTPCluster(clusterName string, clusterServiceName string, mutationFunc ...ClusterMutator) (ciliumv2.XDSResource, error) {
	cluster := &envoy_config_cluster_v3.Cluster{
		Name: clusterName,
		TypedExtensionProtocolOptions: map[string]*anypb.Any{
			httpProtocolOptionsType: toAny(&envoy_upstreams_http_v3.HttpProtocolOptions{
				UpstreamProtocolOptions: &envoy_upstreams_http_v3.HttpProtocolOptions_UseDownstreamProtocolConfig{
					UseDownstreamProtocolConfig: &envoy_upstreams_http_v3.HttpProtocolOptions_UseDownstreamHttpConfig{
						Http2ProtocolOptions: &envoy_config_core_v3.Http2ProtocolOptions{},
					},
				},
			}),
		},
		ClusterDiscoveryType: &envoy_config_cluster_v3.Cluster_Type{
			Type: envoy_config_cluster_v3.Cluster_EDS,
		},
		EdsClusterConfig: &envoy_config_cluster_v3.Cluster_EdsClusterConfig{
			ServiceName: clusterServiceName,
		},
	}

	// Apply mutation functions for customizing the cluster.
	for _, fn := range mutationFunc {
		cluster = fn(cluster)
	}

	clusterBytes, err := proto.Marshal(cluster)
	if err != nil {
		return ciliumv2.XDSResource{}, err
	}

	return ciliumv2.XDSResource{
		Any: &anypb.Any{
			TypeUrl: envoy.ClusterTypeURL,
			Value:   clusterBytes,
		},
	}, nil
}

// NewTCPClusterWithDefaults same as NewTCPCluster but has default mutation functions applied.
// currently this is only used for TLSRoutes to create a passthrough proxy
func NewTCPClusterWithDefaults(clusterName string, clusterServiceName string, mutationFunc ...ClusterMutator) (ciliumv2.XDSResource, error) {
	fns := append(mutationFunc,
		WithConnectionTimeout(5),
		WithClusterLbPolicy(int32(envoy_config_cluster_v3.Cluster_ROUND_ROBIN)),
		WithOutlierDetection(true),
	)
	return NewTCPCluster(clusterName, clusterServiceName, fns...)
}

// NewTCPCluster creates a new Envoy cluster.
func NewTCPCluster(clusterName string, clusterServiceName string, mutationFunc ...ClusterMutator) (ciliumv2.XDSResource, error) {
	cluster := &envoy_config_cluster_v3.Cluster{
		Name: clusterName,
		ClusterDiscoveryType: &envoy_config_cluster_v3.Cluster_Type{
			Type: envoy_config_cluster_v3.Cluster_EDS,
		},
		EdsClusterConfig: &envoy_config_cluster_v3.Cluster_EdsClusterConfig{
			ServiceName: clusterServiceName,
		},
	}

	// Apply mutation functions for customizing the cluster.
	for _, fn := range mutationFunc {
		cluster = fn(cluster)
	}

	clusterBytes, err := proto.Marshal(cluster)
	if err != nil {
		return ciliumv2.XDSResource{}, err
	}

	return ciliumv2.XDSResource{
		Any: &anypb.Any{
			TypeUrl: envoy.ClusterTypeURL,
			Value:   clusterBytes,
		},
	}, nil
}

func toAny(message proto.Message) *anypb.Any {
	a, err := anypb.New(message)
	if err != nil {
		return nil
	}
	return a
}
