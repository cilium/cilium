// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"fmt"

	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/node"
)

const localityClusterName = "/cilium-locality-cluster"

func getLocalNodeZone(localNodeStore *node.LocalNodeStore) (string, error) {
	if localNodeStore == nil {
		return "", nil
	}

	localNode, err := localNodeStore.Get(context.Background())
	if err != nil {
		return "", fmt.Errorf("get local node: %w", err)
	}

	return localNode.Labels[corev1.LabelTopologyZone], nil
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
