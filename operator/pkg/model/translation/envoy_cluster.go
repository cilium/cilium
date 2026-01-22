// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"fmt"
	goslices "slices"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_upstreams_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

const (
	httpProtocolOptionsType = "envoy.extensions.upstreams.http.v3.HttpProtocolOptions"
)

type CircuitBreakerThreshold struct {
	Priority           string
	MaxConnections     *uint32
	MaxPendingRequests *uint32
	MaxRequests        *uint32
	MaxRetries         *uint32
}

type HTTPVersionType int

const (
	HTTPVersionDownstream HTTPVersionType = -1
	HTTPVersionAuto       HTTPVersionType = 0
	HTTPVersion1          HTTPVersionType = 1
	HTTPVersion2          HTTPVersionType = 2
	HTTPVersion3          HTTPVersionType = 3
)

func (i *cecTranslator) clusterMutators(grpcService bool, appProtocol string, thresholds []*CircuitBreakerThreshold, circuitBreakerName string) []ClusterMutator {
	res := []ClusterMutator{
		withIdleTimeout(i.Config.ClusterConfig.IdleTimeoutSeconds),
		withClusterLbPolicy(int32(envoy_config_cluster_v3.Cluster_ROUND_ROBIN)),
		withOutlierDetection(true),
	}
	if thresholds != nil && len(thresholds) > 0 {
		res = append(res, withCircuitBreaker(thresholds, circuitBreakerName))
	}
	if grpcService {
		res = append(res, withProtocol(HTTPVersion2))
	} else if i.Config.ClusterConfig.UseAppProtocol {
		switch appProtocol {
		case AppProtocolH2C:
			res = append(res, withProtocol(HTTPVersion2))
		default:
			// When --use-app-protocol is used, envoy will set upstream protocol to HTTP/1.1
			res = append(res, withProtocol(HTTPVersion1))
		}
	}
	return res
}

func (i *cecTranslator) tcpClusterMutators(mutationFunc ...ClusterMutator) []ClusterMutator {
	return append(mutationFunc,
		withClusterLbPolicy(int32(envoy_config_cluster_v3.Cluster_ROUND_ROBIN)),
		withOutlierDetection(true),
	)
}

func (i *cecTranslator) desiredEnvoyCluster(m *model.Model) ([]ciliumv2.XDSResource, error) {
	envoyClusters := map[string]ciliumv2.XDSResource{}
	var sortedClusterNames []string

	for ns, v := range getNamespaceNamePortsMapForHTTP(m) {
		for name, ports := range v {
			for _, port := range ports {
				clusterName := getClusterName(ns, name, port)
				clusterServiceName := getClusterServiceName(ns, name, port)
				sortedClusterNames = append(sortedClusterNames, clusterName)

				var thresholds []*CircuitBreakerThreshold
				var circuitBreakerName string
				if m.CircuitBreakers != nil {
					key := fmt.Sprintf("%s/%s:%s", ns, name, port)
					if cbInterface, ok := m.CircuitBreakers[key]; ok {
						if cb, ok := cbInterface.(*ciliumv2.CiliumEnvoyCircuitBreaker); ok {
							thresholds = convertCircuitBreakerToThresholds(cb)
							circuitBreakerName = fmt.Sprintf("%s/%s", cb.GetNamespace(), cb.GetName())
						}
					}
				}

				envoyClusters[clusterName], _ = i.httpCluster(clusterName, clusterServiceName,
					isGRPCService(m, ns, name, port),
					getAppProtocol(m, ns, name, port),
					thresholds, circuitBreakerName)
			}
		}
	}

	for ns, v := range getNamespaceNamePortsMapForTLS(m) {
		for name, ports := range v {
			for _, port := range ports {
				clusterName := getClusterName(ns, name, port)
				clusterServiceName := getClusterServiceName(ns, name, port)
				sortedClusterNames = append(sortedClusterNames, clusterName)
				envoyClusters[clusterName], _ = i.tcpCluster(clusterName, clusterServiceName)
			}
		}
	}

	goslices.Sort(sortedClusterNames)
	res := make([]ciliumv2.XDSResource, len(sortedClusterNames))
	for i, name := range sortedClusterNames {
		res[i] = envoyClusters[name]
	}

	return res, nil
}

func convertCircuitBreakerToThresholds(cb *ciliumv2.CiliumEnvoyCircuitBreaker) []*CircuitBreakerThreshold {
	if cb == nil || len(cb.Spec.Thresholds) == 0 {
		return nil
	}

	var thresholds []*CircuitBreakerThreshold
	for _, t := range cb.Spec.Thresholds {
		thresholds = append(thresholds, &CircuitBreakerThreshold{
			Priority:           t.Priority,
			MaxConnections:     t.MaxConnections,
			MaxPendingRequests: t.MaxPendingRequests,
			MaxRequests:        t.MaxRequests,
			MaxRetries:         t.MaxRetries,
		})
	}
	return thresholds
}

// httpCluster creates a new Envoy cluster.
func (i *cecTranslator) httpCluster(clusterName string, clusterServiceName string, isGRPCService bool, appProtocol string, thresholds []*CircuitBreakerThreshold, circuitBreakerName string) (ciliumv2.XDSResource, error) {
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
	for _, fn := range i.clusterMutators(isGRPCService, appProtocol, thresholds, circuitBreakerName) {
		cluster = fn(cluster)
	}

	return toXdsResource(cluster, envoy.ClusterTypeURL)
}

// tcpCluster same as NewTCPCluster but has default mutation functions applied.
// currently this is only used for TLSRoutes to create a passthrough proxy
func (i *cecTranslator) tcpCluster(clusterName string, clusterServiceName string, mutationFunc ...ClusterMutator) (ciliumv2.XDSResource, error) {
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
	for _, fn := range i.tcpClusterMutators(mutationFunc...) {
		cluster = fn(cluster)
	}

	return toXdsResource(cluster, envoy.ClusterTypeURL)
}

func getClusterName(ns, name, port string) string {
	// the name is having the format of "namespace:name:port"
	// -> slash would prevent ParseResources from rewriting with CEC namespace and name!
	return fmt.Sprintf("%s:%s:%s", ns, name, port)
}

func getClusterServiceName(ns, name, port string) string {
	// the name is having the format of "namespace/name:port"
	return fmt.Sprintf("%s/%s:%s", ns, name, port)
}

// getNamespaceNamePortsMapForHTTP returns a map of namespace -> name -> ports.
// The ports are sorted and unique.
func getNamespaceNamePortsMapForHTTP(m *model.Model) map[string]map[string][]string {
	namespaceNamePortMap := map[string]map[string][]string{}
	for _, l := range m.HTTP {
		for _, r := range l.Routes {
			mergeBackendsInNamespaceNamePortMap(r.Backends, namespaceNamePortMap)
			for _, rm := range r.RequestMirrors {
				if rm.Backend == nil {
					continue
				}
				mergeBackendsInNamespaceNamePortMap([]model.Backend{*rm.Backend}, namespaceNamePortMap)
			}
		}
	}
	return namespaceNamePortMap
}

// getNamespaceNamePortsMapFroTLS returns a map of namespace -> name -> ports.
// The ports are sorted and unique.
func getNamespaceNamePortsMapForTLS(m *model.Model) map[string]map[string][]string {
	namespaceNamePortMap := map[string]map[string][]string{}
	for _, l := range m.TLSPassthrough {
		for _, r := range l.Routes {
			mergeBackendsInNamespaceNamePortMap(r.Backends, namespaceNamePortMap)
		}
	}
	return namespaceNamePortMap
}
