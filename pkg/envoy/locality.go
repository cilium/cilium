// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"fmt"

	envoy_config_bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/node"
)

const localityClusterName = "/cilium-locality-cluster"

func getLocalNodeZone(localNodeStore *node.LocalNodeStore) (string, error) {
	if localNodeStore == nil {
		return "", fmt.Errorf("local node store is unavailable")
	}

	localNode, err := localNodeStore.Get(context.Background())
	if err != nil {
		return "", fmt.Errorf("get local node: %w", err)
	}

	return localNode.Labels[corev1.LabelTopologyZone], nil
}

func appendEmbeddedLocalityBootstrap(bs *envoy_config_bootstrap.Bootstrap, connectTimeout int64, zone string) {
	if bs.GetNode() == nil {
		bs.Node = &envoy_config_core.Node{}
	}
	if bs.StaticResources == nil {
		bs.StaticResources = &envoy_config_bootstrap.Bootstrap_StaticResources{}
	}
	if bs.ClusterManager == nil {
		bs.ClusterManager = &envoy_config_bootstrap.ClusterManager{}
	}
	bs.ClusterManager.LocalClusterName = localityClusterName
	bs.StaticResources.Clusters = append(bs.StaticResources.Clusters, newLocalityCluster(connectTimeout))

	if zone != "" {
		bs.Node.Locality = &envoy_config_core.Locality{Zone: zone}
	}
}

// newLocalityCluster defines the internal EDS-backed local cluster Envoy uses for locality-aware routing.
func newLocalityCluster(connectTimeout int64) *envoy_config_cluster.Cluster {
	return &envoy_config_cluster.Cluster{
		Name:                 localityClusterName,
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
		ConnectTimeout:       &durationpb.Duration{Seconds: connectTimeout},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{
			EdsConfig: &envoy_config_core.ConfigSource{
				ResourceApiVersion: envoy_config_core.ApiVersion_V3,
				ConfigSourceSpecifier: &envoy_config_core.ConfigSource_ApiConfigSource{
					ApiConfigSource: &envoy_config_core.ApiConfigSource{
						ApiType:                   envoy_config_core.ApiConfigSource_GRPC,
						TransportApiVersion:       envoy_config_core.ApiVersion_V3,
						SetNodeOnFirstMessageOnly: true,
						GrpcServices: []*envoy_config_core.GrpcService{{
							TargetSpecifier: &envoy_config_core.GrpcService_EnvoyGrpc_{
								EnvoyGrpc: &envoy_config_core.GrpcService_EnvoyGrpc{
									ClusterName: CiliumXDSClusterName,
								},
							},
						}},
					},
				},
			},
			ServiceName: localityClusterName,
		},
		LbPolicy: envoy_config_cluster.Cluster_ROUND_ROBIN,
	}
}
