// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"testing"

	envoy_config_cluster "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	http_connection_manager_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/stretchr/testify/require"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func Test_grpcHttpConnectionManagerMutator(t *testing.T) {
	input := &http_connection_manager_v3.HttpConnectionManager{}

	t.Run("mutate upgradeConfigs", func(t *testing.T) {
		res := grpcHttpConnectionManagerMutator(&slim_corev1.Service{
			ObjectMeta: slim_metav1.ObjectMeta{},
		})(input)
		require.NotNil(t, res)
		require.NotNil(t, res.UpgradeConfigs)
	})
}

func Test_lbModeClusterMutator(t *testing.T) {
	input := &envoy_config_cluster.Cluster{}

	t.Run("no ops", func(t *testing.T) {
		res := lbModeClusterMutator(&slim_corev1.Service{})(input)
		require.NotNil(t, res)
		require.Equal(t, envoy_config_cluster.Cluster_LbPolicy(0), res.LbPolicy)
	})

	t.Run("mutate lb policy to round robin", func(t *testing.T) {
		res := lbModeClusterMutator(&slim_corev1.Service{
			ObjectMeta: slim_metav1.ObjectMeta{
				Annotations: map[string]string{
					lbModeAnnotation: "round_robin",
				},
			},
		})(input)
		require.NotNil(t, res)
		require.NotNil(t, res.LbPolicy, envoy_config_cluster.Cluster_ROUND_ROBIN)
	})

	t.Run("mutate lb policy to least request", func(t *testing.T) {
		res := lbModeClusterMutator(&slim_corev1.Service{
			ObjectMeta: slim_metav1.ObjectMeta{
				Annotations: map[string]string{
					lbModeAnnotation: "least_request",
				},
			},
		})(input)
		require.NotNil(t, res)
		require.NotNil(t, res.LbPolicy, envoy_config_cluster.Cluster_LEAST_REQUEST)
	})
}
