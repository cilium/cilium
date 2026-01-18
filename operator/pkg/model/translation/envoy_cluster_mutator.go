// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_upstreams_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type ClusterMutator func(*envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster

// withClusterLbPolicy sets the cluster's load balancing policy.
// https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/load_balancers
func withClusterLbPolicy(lbPolicy int32) ClusterMutator {
	return func(cluster *envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster {
		if cluster == nil {
			return cluster
		}
		cluster.LbPolicy = envoy_config_cluster_v3.Cluster_LbPolicy(lbPolicy)
		return cluster
	}
}

// withOutlierDetection enables outlier detection on the cluster.
func withOutlierDetection(splitExternalLocalOriginErrors bool) ClusterMutator {
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

// withConnectionTimeout sets the cluster's connection timeout.
func withConnectionTimeout(seconds int) ClusterMutator {
	return func(cluster *envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster {
		if cluster == nil {
			return cluster
		}
		cluster.ConnectTimeout = &durationpb.Duration{Seconds: int64(seconds)}
		return cluster
	}
}

// withIdleTimeout sets the cluster's connection idle timeout.
func withIdleTimeout(seconds int) ClusterMutator {
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

func withProtocol(protocolVersion HTTPVersionType) ClusterMutator {
	return func(cluster *envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster {
		a := cluster.TypedExtensionProtocolOptions[httpProtocolOptionsType]
		options := &envoy_upstreams_http_v3.HttpProtocolOptions{}
		if err := a.UnmarshalTo(options); err != nil {
			return cluster
		}
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

func withCircuitBreaker(thresholds []*CircuitBreakerThreshold, circuitBreakerName string) ClusterMutator {
	return func(cluster *envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster {
		if cluster == nil {
			return cluster
		}

		if thresholds == nil || len(thresholds) == 0 {
			return cluster
		}

		envoyThresholds := []*envoy_config_cluster_v3.CircuitBreakers_Thresholds{}

		for _, t := range thresholds {
			var priority envoy_config_core_v3.RoutingPriority
			switch t.Priority {
			case "HIGH":
				priority = envoy_config_core_v3.RoutingPriority_HIGH
			case "DEFAULT":
				priority = envoy_config_core_v3.RoutingPriority_DEFAULT
			default:
				priority = envoy_config_core_v3.RoutingPriority_DEFAULT
			}

			envoyThreshold := &envoy_config_cluster_v3.CircuitBreakers_Thresholds{
				Priority: priority,
			}

			if t.MaxConnections != nil {
				envoyThreshold.MaxConnections = wrapperspb.UInt32(*t.MaxConnections)
			}
			if t.MaxPendingRequests != nil {
				envoyThreshold.MaxPendingRequests = wrapperspb.UInt32(*t.MaxPendingRequests)
			}
			if t.MaxRequests != nil {
				envoyThreshold.MaxRequests = wrapperspb.UInt32(*t.MaxRequests)
			}
			if t.MaxRetries != nil {
				envoyThreshold.MaxRetries = wrapperspb.UInt32(*t.MaxRetries)
			}

			envoyThresholds = append(envoyThresholds, envoyThreshold)
		}

		cluster.CircuitBreakers = &envoy_config_cluster_v3.CircuitBreakers{
			Thresholds: envoyThresholds,
		}

		return cluster
	}
}
