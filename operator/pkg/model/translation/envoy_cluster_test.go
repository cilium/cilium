// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func Test_withClusterLbPolicy(t *testing.T) {
	fn := withClusterLbPolicy(int32(envoy_config_cluster_v3.Cluster_LEAST_REQUEST))

	t.Run("input is nil", func(t *testing.T) {
		cluster := fn(nil)
		require.Nil(t, cluster)
	})

	t.Run("input is not nil", func(t *testing.T) {
		cluster := &envoy_config_cluster_v3.Cluster{}
		cluster = fn(cluster)
		require.Equal(t, envoy_config_cluster_v3.Cluster_LEAST_REQUEST, cluster.LbPolicy)
	})
}

func Test_withOutlierDetection(t *testing.T) {
	t.Run("input is nil", func(t *testing.T) {
		fn := withOutlierDetection(true)
		cluster := fn(nil)
		require.Nil(t, cluster)
	})

	t.Run("input is not nil", func(t *testing.T) {
		t.Run("enabled", func(t *testing.T) {
			fn := withOutlierDetection(true)
			cluster := &envoy_config_cluster_v3.Cluster{}
			cluster = fn(cluster)
			require.NotNil(t, cluster.OutlierDetection)
			require.True(t, cluster.OutlierDetection.SplitExternalLocalOriginErrors)
		})

		t.Run("disabled", func(t *testing.T) {
			fn := withOutlierDetection(false)
			cluster := &envoy_config_cluster_v3.Cluster{}
			cluster = fn(cluster)
			require.NotNil(t, cluster.OutlierDetection)
			require.False(t, cluster.OutlierDetection.SplitExternalLocalOriginErrors)
		})
	})
}

func Test_withConnectionTimeout(t *testing.T) {
	fn := withConnectionTimeout(10)

	t.Run("input is nil", func(t *testing.T) {
		cluster := fn(nil)
		require.Nil(t, cluster)
	})

	t.Run("input is not nil", func(t *testing.T) {
		cluster := &envoy_config_cluster_v3.Cluster{}
		cluster = fn(cluster)
		require.Equal(t, int64(10), cluster.ConnectTimeout.Seconds)
	})
}

func Test_httpCluster(t *testing.T) {
	c := &cecTranslator{}
	res, err := c.httpCluster("dummy-name", "dummy-name", false, "", nil, "")
	require.NoError(t, err)

	cluster := &envoy_config_cluster_v3.Cluster{}
	err = proto.Unmarshal(res.Value, cluster)

	require.NoError(t, err)
	require.Equal(t, "dummy-name", cluster.Name)
	require.Equal(t, &envoy_config_cluster_v3.Cluster_Type{
		Type: envoy_config_cluster_v3.Cluster_EDS,
	}, cluster.ClusterDiscoveryType)
}

func Test_tcpCluster(t *testing.T) {
	c := &cecTranslator{}
	res, err := c.tcpCluster("dummy-name", "dummy-name")
	require.NoError(t, err)

	cluster := &envoy_config_cluster_v3.Cluster{}
	err = proto.Unmarshal(res.Value, cluster)

	require.NoError(t, err)
	require.Equal(t, "dummy-name", cluster.Name)
	require.Equal(t, &envoy_config_cluster_v3.Cluster_Type{
		Type: envoy_config_cluster_v3.Cluster_EDS,
	}, cluster.ClusterDiscoveryType)
}

func Test_withCircuitBreaker(t *testing.T) {
	t.Run("input is nil", func(t *testing.T) {
		fn := withCircuitBreaker(nil, "")
		cluster := fn(nil)
		require.Nil(t, cluster)
	})

	t.Run("thresholds is nil", func(t *testing.T) {
		fn := withCircuitBreaker(nil, "")
		cluster := &envoy_config_cluster_v3.Cluster{}
		cluster = fn(cluster)
		require.Nil(t, cluster.CircuitBreakers)
	})

	t.Run("thresholds is empty", func(t *testing.T) {
		fn := withCircuitBreaker([]*CircuitBreakerThreshold{}, "")
		cluster := &envoy_config_cluster_v3.Cluster{}
		cluster = fn(cluster)
		require.Nil(t, cluster.CircuitBreakers)
	})

	t.Run("single threshold with DEFAULT priority", func(t *testing.T) {
		maxConn := uint32(1000)
		maxPending := uint32(2000)
		maxRequests := uint32(3000)
		maxRetries := uint32(100)
		thresholds := []*CircuitBreakerThreshold{
			{
				Priority:           "DEFAULT",
				MaxConnections:     &maxConn,
				MaxPendingRequests: &maxPending,
				MaxRequests:        &maxRequests,
				MaxRetries:         &maxRetries,
			},
		}
		fn := withCircuitBreaker(thresholds, "test/cb")
		cluster := &envoy_config_cluster_v3.Cluster{}
		cluster = fn(cluster)

		require.NotNil(t, cluster.CircuitBreakers)
		require.Len(t, cluster.CircuitBreakers.Thresholds, 1)
		threshold := cluster.CircuitBreakers.Thresholds[0]
		require.Equal(t, envoy_config_core_v3.RoutingPriority_DEFAULT, threshold.Priority)
		require.NotNil(t, threshold.MaxConnections)
		require.Equal(t, uint32(1000), threshold.MaxConnections.Value)
		require.NotNil(t, threshold.MaxPendingRequests)
		require.Equal(t, uint32(2000), threshold.MaxPendingRequests.Value)
		require.NotNil(t, threshold.MaxRequests)
		require.Equal(t, uint32(3000), threshold.MaxRequests.Value)
		require.NotNil(t, threshold.MaxRetries)
		require.Equal(t, uint32(100), threshold.MaxRetries.Value)
	})

	t.Run("single threshold with HIGH priority", func(t *testing.T) {
		maxConn := uint32(5000)
		thresholds := []*CircuitBreakerThreshold{
			{
				Priority:       "HIGH",
				MaxConnections: &maxConn,
			},
		}
		fn := withCircuitBreaker(thresholds, "test/cb")
		cluster := &envoy_config_cluster_v3.Cluster{}
		cluster = fn(cluster)

		require.NotNil(t, cluster.CircuitBreakers)
		require.Len(t, cluster.CircuitBreakers.Thresholds, 1)
		threshold := cluster.CircuitBreakers.Thresholds[0]
		require.Equal(t, envoy_config_core_v3.RoutingPriority_HIGH, threshold.Priority)
		require.NotNil(t, threshold.MaxConnections)
		require.Equal(t, uint32(5000), threshold.MaxConnections.Value)
	})

	t.Run("multiple thresholds", func(t *testing.T) {
		maxConnDefault := uint32(1000)
		maxConnHigh := uint32(5000)
		thresholds := []*CircuitBreakerThreshold{
			{
				Priority:       "DEFAULT",
				MaxConnections: &maxConnDefault,
			},
			{
				Priority:       "HIGH",
				MaxConnections: &maxConnHigh,
			},
		}
		fn := withCircuitBreaker(thresholds, "test/cb")
		cluster := &envoy_config_cluster_v3.Cluster{}
		cluster = fn(cluster)

		require.NotNil(t, cluster.CircuitBreakers)
		require.Len(t, cluster.CircuitBreakers.Thresholds, 2)
		require.Equal(t, envoy_config_core_v3.RoutingPriority_DEFAULT, cluster.CircuitBreakers.Thresholds[0].Priority)
		require.Equal(t, envoy_config_core_v3.RoutingPriority_HIGH, cluster.CircuitBreakers.Thresholds[1].Priority)
	})

	t.Run("threshold with nil values", func(t *testing.T) {
		thresholds := []*CircuitBreakerThreshold{
			{
				Priority:           "DEFAULT",
				MaxConnections:     nil,
				MaxPendingRequests: nil,
				MaxRequests:        nil,
				MaxRetries:         nil,
			},
		}
		fn := withCircuitBreaker(thresholds, "test/cb")
		cluster := &envoy_config_cluster_v3.Cluster{}
		cluster = fn(cluster)

		require.NotNil(t, cluster.CircuitBreakers)
		require.Len(t, cluster.CircuitBreakers.Thresholds, 1)
		threshold := cluster.CircuitBreakers.Thresholds[0]
		require.Equal(t, envoy_config_core_v3.RoutingPriority_DEFAULT, threshold.Priority)
		require.Nil(t, threshold.MaxConnections)
		require.Nil(t, threshold.MaxPendingRequests)
		require.Nil(t, threshold.MaxRequests)
		require.Nil(t, threshold.MaxRetries)
	})

	t.Run("invalid priority defaults to DEFAULT", func(t *testing.T) {
		maxConn := uint32(1000)
		thresholds := []*CircuitBreakerThreshold{
			{
				Priority:       "INVALID",
				MaxConnections: &maxConn,
			},
		}
		fn := withCircuitBreaker(thresholds, "test/cb")
		cluster := &envoy_config_cluster_v3.Cluster{}
		cluster = fn(cluster)

		require.NotNil(t, cluster.CircuitBreakers)
		require.Len(t, cluster.CircuitBreakers.Thresholds, 1)
		threshold := cluster.CircuitBreakers.Thresholds[0]
		require.Equal(t, envoy_config_core_v3.RoutingPriority_DEFAULT, threshold.Priority)
	})
}
