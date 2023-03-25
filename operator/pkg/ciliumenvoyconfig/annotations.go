// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"strings"

	envoy_config_cluster_v3 "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	http_connection_manager_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/annotation"
)

const (
	lbEnabledAnnotation = annotation.ServicePrefix + "/lb-l7"
	lbModeAnnotation    = annotation.ServicePrefix + "/lb-l7-algorithm"
)

type clusterMutator func(*envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster
type httpConnectionManagerMutator func(*http_connection_manager_v3.HttpConnectionManager) *http_connection_manager_v3.HttpConnectionManager
type listenerMutator func(*envoy_config_listener.Listener) *envoy_config_listener.Listener
type routeMutator func(route *envoy_config_route_v3.Route) *envoy_config_route_v3.Route
type routeConfigMutator func(*envoy_config_route_v3.RouteConfiguration) *envoy_config_route_v3.RouteConfiguration
type virtualHostMutator func(*envoy_config_route_v3.VirtualHost) *envoy_config_route_v3.VirtualHost

// IsLBProtocolAnnotationEnabled returns true if the load balancer protocol is enabled
func IsLBProtocolAnnotationEnabled(obj metav1.Object) bool {
	return obj.GetAnnotations()[lbEnabledAnnotation] == "enabled"
}

// GetLBProtocolModelAnnotation returns the load balancer mode
func GetLBProtocolModelAnnotation(obj metav1.Object) string {
	return obj.GetAnnotations()[lbModeAnnotation]
}

//
// ClusterMutator functions
//

// grpcHttpConnectionManagerMutator returns a function that mutates the upgradeConfigs for grpc protocol
func lbModeClusterMutator(obj metav1.Object) clusterMutator {
	return func(cluster *envoy_config_cluster_v3.Cluster) *envoy_config_cluster_v3.Cluster {
		lbMode := GetLBProtocolModelAnnotation(obj)
		if lbMode == "" {
			return cluster
		}

		cluster.LbPolicy = envoy_config_cluster_v3.Cluster_LbPolicy(envoy_config_cluster_v3.Cluster_LbPolicy_value[strings.ToUpper(lbMode)])
		return cluster
	}
}

//
// HTTPConnectionManagerMutator functions
//

// grpcHttpConnectionManagerMutator returns a function that mutates the upgradeConfigs for grpc protocol
func grpcHttpConnectionManagerMutator(_ metav1.Object) httpConnectionManagerMutator {
	return func(manager *http_connection_manager_v3.HttpConnectionManager) *http_connection_manager_v3.HttpConnectionManager {
		manager.UpgradeConfigs = []*http_connection_manager_v3.HttpConnectionManager_UpgradeConfig{
			{UpgradeType: "websocket"},
		}
		return manager
	}
}
