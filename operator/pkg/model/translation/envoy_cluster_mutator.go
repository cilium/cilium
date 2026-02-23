// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_upstreams_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/cilium/cilium/operator/pkg/model"
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

func withTLSOrigination(tls *model.BackendTLSOrigination) ClusterMutator {
	return func(cluster *envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster {
		// This mutator should not get added to the list if this is the case, but just to be safe.
		if tls == nil {
			return cluster
		}

		// If there is no SNI set, we should not originate TLS.
		if tls.SNI == "" {
			return cluster
		}

		if tls.CACertRef == nil || tls.CACertRef.Name == "" || tls.CACertRef.Namespace == "" {
			return cluster
		}

		tlsContext := &envoy_config_tls.UpstreamTlsContext{
			Sni: tls.SNI,
			CommonTlsContext: &envoy_config_tls.CommonTlsContext{
				ValidationContextType: &envoy_config_tls.CommonTlsContext_CombinedValidationContext{
					CombinedValidationContext: &envoy_config_tls.CommonTlsContext_CombinedCertificateValidationContext{
						DefaultValidationContext: &envoy_config_tls.CertificateValidationContext{},
						ValidationContextSdsSecretConfig: &envoy_config_tls.SdsSecretConfig{
							// This secret is synchronized by the secretsyncer Cell, with the Secret being copied
							// out of the relevant ConfigMap by the ConfigMap sync Reconcile function there, which itself
							// watches for ConfigMaps referenced in BackendTLSPolicy objects.
							//
							// That is, the flow is:
							//
							// * BackendTLSPolicy references ConfigMap
							// * SecretSync sees ConfigMap reference
							// * SecretSync copies ConfigMap into Secret in cilium-secrets namespace, using the below
							//   naming format
							// * This translation references that Secret
							// * The Cilium Agent reads the Secret directly and suppies it to Envoy via SDS.
							Name: "cilium-secrets" + "/" + tls.CACertRef.Namespace + "-cfgmap-" + tls.CACertRef.Name,
						},
					},
				},
			},
		}

		cluster.TransportSocket = &envoy_config_core_v3.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &envoy_config_core.TransportSocket_TypedConfig{
				TypedConfig: toAny(tlsContext),
			},
		}
		return cluster
	}
}
