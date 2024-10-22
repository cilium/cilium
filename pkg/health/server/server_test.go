// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"bufio"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/common/expfmt"
	"github.com/stretchr/testify/require"

	healthModels "github.com/cilium/cilium/api/v1/health/models"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	latencyMetricName = "cilium_node_health_connectivity_latency_seconds"
	statusMetricName  = "cilium_node_health_connectivity_status"
)

var sampleSingleClusterConnectivity = &healthReport{
	nodes: []*healthModels.NodeStatus{
		{
			HealthEndpoint: &healthModels.EndpointStatus{
				PrimaryAddress: &healthModels.PathStatus{
					HTTP: &healthModels.ConnectivityStatus{
						Latency: 2121004,
					},
					Icmp: &healthModels.ConnectivityStatus{
						Latency: 672600,
					},
					IP: "10.244.3.219",
				},
				SecondaryAddresses: []*healthModels.PathStatus{
					{
						HTTP: &healthModels.ConnectivityStatus{
							Latency: 5121015,
						},
						Icmp: &healthModels.ConnectivityStatus{
							Latency: 672601,
						},
						IP: "10.244.3.220",
					},
				},
			},
			Host: &healthModels.HostStatus{
				PrimaryAddress: &healthModels.PathStatus{
					HTTP: &healthModels.ConnectivityStatus{
						Latency: 1653627,
					},
					Icmp: &healthModels.ConnectivityStatus{
						Latency: 7041796,
					},
					IP: "172.18.0.3",
				},
				SecondaryAddresses: []*healthModels.PathStatus{
					{
						HTTP: &healthModels.ConnectivityStatus{
							Latency: 21210242,
						},
						Icmp: &healthModels.ConnectivityStatus{
							Latency: 672603,
						},
						IP: "172.18.0.4",
					},
				},
			},
			Name: "kind-worker",
		},
	},
}

var sampleClustermeshConnectivity = &healthReport{
	nodes: []*healthModels.NodeStatus{
		{
			HealthEndpoint: &healthModels.EndpointStatus{
				PrimaryAddress: &healthModels.PathStatus{
					HTTP: &healthModels.ConnectivityStatus{
						Latency: 3121005,
					},
					Icmp: &healthModels.ConnectivityStatus{
						Latency: 772600,
					},
					IP: "10.244.3.219",
				},
				SecondaryAddresses: []*healthModels.PathStatus{
					{
						HTTP: &healthModels.ConnectivityStatus{
							Latency: 3121015,
						},
						Icmp: &healthModels.ConnectivityStatus{
							Latency: 772601,
						},
						IP: "10.244.3.220",
					},
				},
			},
			Host: &healthModels.HostStatus{
				PrimaryAddress: &healthModels.PathStatus{
					HTTP: &healthModels.ConnectivityStatus{
						Latency: 165362,
					},
					Icmp: &healthModels.ConnectivityStatus{
						Latency: 7041793,
					},
					IP: "172.18.0.1",
				},
				SecondaryAddresses: []*healthModels.PathStatus{
					{
						HTTP: &healthModels.ConnectivityStatus{
							Latency: 312105,
						},
						Icmp: &healthModels.ConnectivityStatus{
							Latency: 7726063,
						},
						IP: "172.18.0.2",
					},
				},
			},
			Name: "kind-cilium-mesh-1/kind-cilium-mesh-1-worker",
		},
		{
			HealthEndpoint: &healthModels.EndpointStatus{
				PrimaryAddress: &healthModels.PathStatus{
					HTTP: &healthModels.ConnectivityStatus{
						Latency: 274815,
					},
					Icmp: &healthModels.ConnectivityStatus{
						Latency: 5837115,
					},
					IP: "10.1.2.143",
				},
				SecondaryAddresses: []*healthModels.PathStatus{
					{
						HTTP: &healthModels.ConnectivityStatus{
							Latency: 212101,
						},
						Icmp: &healthModels.ConnectivityStatus{
							Latency: 6726012,
						},
						IP: "10.1.2.144",
					},
				},
			},
			Host: &healthModels.HostStatus{
				PrimaryAddress: &healthModels.PathStatus{
					HTTP: &healthModels.ConnectivityStatus{
						Latency: 1661017,
					},
					Icmp: &healthModels.ConnectivityStatus{
						Latency: 635688,
					},
					IP: "172.18.0.3",
				},
				SecondaryAddresses: []*healthModels.PathStatus{
					{
						HTTP: &healthModels.ConnectivityStatus{
							Latency: 212103,
						},
						Icmp: &healthModels.ConnectivityStatus{
							Latency: 6726034,
						},
						IP: "172.18.0.4",
					},
				},
			},
			Name: "kind-cilium-mesh-2/kind-cilium-mesh-2-worker",
		},
	},
}

var sampleSingleClusterConnectivityBroken = &healthReport{
	nodes: []*healthModels.NodeStatus{
		{
			HealthEndpoint: &healthModels.EndpointStatus{
				PrimaryAddress: &healthModels.PathStatus{
					HTTP: &healthModels.ConnectivityStatus{
						Status: "failed",
					},
					Icmp: &healthModels.ConnectivityStatus{
						Status: "failed",
					},
					IP: "10.244.3.219",
				},
				SecondaryAddresses: []*healthModels.PathStatus{
					{
						HTTP: &healthModels.ConnectivityStatus{
							Latency: 5121015,
						},
						Icmp: &healthModels.ConnectivityStatus{
							Latency: 672601,
						},
						IP: "10.244.3.220",
					},
				},
			},
			Host: &healthModels.HostStatus{
				PrimaryAddress: &healthModels.PathStatus{
					HTTP: &healthModels.ConnectivityStatus{
						Latency: 1653627,
					},
					Icmp: &healthModels.ConnectivityStatus{
						Latency: 7041796,
					},
					IP: "172.18.0.3",
				},
				SecondaryAddresses: []*healthModels.PathStatus{
					{
						HTTP: &healthModels.ConnectivityStatus{
							Status: "failed",
						},
						Icmp: &healthModels.ConnectivityStatus{
							Status: "failed",
						},
						IP: "172.18.0.4",
					},
				},
			},
			Name: "kind-worker",
		},
	},
}

var expectedSingleClusterMetric = map[string]string{
	"cilium_node_health_connectivity_latency_seconds": `# HELP cilium_node_health_connectivity_latency_seconds The histogram for last observed latency between the current Cilium agent and other Cilium nodes in seconds
# TYPE cilium_node_health_connectivity_latency_seconds histogram
cilium_node_health_connectivity_latency_seconds_sum{address_type="primary",protocol="http",source_cluster="default",source_node_name="kind-worker",type="endpoint"} 0.002121004
cilium_node_health_connectivity_latency_seconds_count{address_type="primary",protocol="http",source_cluster="default",source_node_name="kind-worker",type="endpoint"} 1
cilium_node_health_connectivity_latency_seconds_sum{address_type="primary",protocol="http",source_cluster="default",source_node_name="kind-worker",type="node"} 0.001653627
cilium_node_health_connectivity_latency_seconds_count{address_type="primary",protocol="http",source_cluster="default",source_node_name="kind-worker",type="node"} 1
cilium_node_health_connectivity_latency_seconds_sum{address_type="primary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",type="endpoint"} 0.0006726
cilium_node_health_connectivity_latency_seconds_count{address_type="primary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",type="endpoint"} 1
cilium_node_health_connectivity_latency_seconds_sum{address_type="primary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",type="node"} 0.007041796
cilium_node_health_connectivity_latency_seconds_count{address_type="primary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",type="node"} 1
cilium_node_health_connectivity_latency_seconds_sum{address_type="secondary",protocol="http",source_cluster="default",source_node_name="kind-worker",type="endpoint"} 0.005121015
cilium_node_health_connectivity_latency_seconds_count{address_type="secondary",protocol="http",source_cluster="default",source_node_name="kind-worker",type="endpoint"} 1
cilium_node_health_connectivity_latency_seconds_sum{address_type="secondary",protocol="http",source_cluster="default",source_node_name="kind-worker",type="node"} 0.021210242
cilium_node_health_connectivity_latency_seconds_count{address_type="secondary",protocol="http",source_cluster="default",source_node_name="kind-worker",type="node"} 1
cilium_node_health_connectivity_latency_seconds_sum{address_type="secondary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",type="endpoint"} 0.000672601
cilium_node_health_connectivity_latency_seconds_count{address_type="secondary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",type="endpoint"} 1
cilium_node_health_connectivity_latency_seconds_sum{address_type="secondary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",type="node"} 0.000672603
cilium_node_health_connectivity_latency_seconds_count{address_type="secondary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",type="node"} 1
`,
	"cilium_node_health_connectivity_status": `# HELP cilium_node_health_connectivity_status The number of endpoints with last observed status of both ICMP and HTTP connectivity between the current Cilium agent and other Cilium nodes
# TYPE cilium_node_health_connectivity_status gauge
cilium_node_health_connectivity_status{source_cluster="default",source_node_name="kind-worker",status="reachable",type="endpoint"} 2
cilium_node_health_connectivity_status{source_cluster="default",source_node_name="kind-worker",status="reachable",type="node"} 2
cilium_node_health_connectivity_status{source_cluster="default",source_node_name="kind-worker",status="unknown",type="endpoint"} 0
cilium_node_health_connectivity_status{source_cluster="default",source_node_name="kind-worker",status="unknown",type="node"} 0
cilium_node_health_connectivity_status{source_cluster="default",source_node_name="kind-worker",status="unreachable",type="endpoint"} 0
cilium_node_health_connectivity_status{source_cluster="default",source_node_name="kind-worker",status="unreachable",type="node"} 0
`,
}

var expectedClustermeshMetric = map[string]string{
	"cilium_node_health_connectivity_latency_seconds": `# HELP cilium_node_health_connectivity_latency_seconds The histogram for last observed latency between the current Cilium agent and other Cilium nodes in seconds
# TYPE cilium_node_health_connectivity_latency_seconds histogram
cilium_node_health_connectivity_latency_seconds_sum{address_type="primary",protocol="http",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",type="endpoint"} 0.00339582
cilium_node_health_connectivity_latency_seconds_count{address_type="primary",protocol="http",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",type="endpoint"} 2
cilium_node_health_connectivity_latency_seconds_sum{address_type="primary",protocol="http",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",type="node"} 0.0018263790000000002
cilium_node_health_connectivity_latency_seconds_count{address_type="primary",protocol="http",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",type="node"} 2
cilium_node_health_connectivity_latency_seconds_sum{address_type="primary",protocol="icmp",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",type="endpoint"} 0.006609715
cilium_node_health_connectivity_latency_seconds_count{address_type="primary",protocol="icmp",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",type="endpoint"} 2
cilium_node_health_connectivity_latency_seconds_sum{address_type="primary",protocol="icmp",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",type="node"} 0.007677481
cilium_node_health_connectivity_latency_seconds_count{address_type="primary",protocol="icmp",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",type="node"} 2
cilium_node_health_connectivity_latency_seconds_sum{address_type="secondary",protocol="http",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",type="endpoint"} 0.003333116
cilium_node_health_connectivity_latency_seconds_count{address_type="secondary",protocol="http",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",type="endpoint"} 2
cilium_node_health_connectivity_latency_seconds_sum{address_type="secondary",protocol="http",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",type="node"} 0.000524208
cilium_node_health_connectivity_latency_seconds_count{address_type="secondary",protocol="http",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",type="node"} 2
cilium_node_health_connectivity_latency_seconds_sum{address_type="secondary",protocol="icmp",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",type="endpoint"} 0.007498613
cilium_node_health_connectivity_latency_seconds_count{address_type="secondary",protocol="icmp",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",type="endpoint"} 2
cilium_node_health_connectivity_latency_seconds_sum{address_type="secondary",protocol="icmp",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",type="node"} 0.014452097
cilium_node_health_connectivity_latency_seconds_count{address_type="secondary",protocol="icmp",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",type="node"} 2
`,
	"cilium_node_health_connectivity_status": `# HELP cilium_node_health_connectivity_status The number of endpoints with last observed status of both ICMP and HTTP connectivity between the current Cilium agent and other Cilium nodes
# TYPE cilium_node_health_connectivity_status gauge
cilium_node_health_connectivity_status{source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",status="reachable",type="endpoint"} 4
cilium_node_health_connectivity_status{source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",status="reachable",type="node"} 4
cilium_node_health_connectivity_status{source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",status="unknown",type="endpoint"} 0
cilium_node_health_connectivity_status{source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",status="unknown",type="node"} 0
cilium_node_health_connectivity_status{source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",status="unreachable",type="endpoint"} 0
cilium_node_health_connectivity_status{source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",status="unreachable",type="node"} 0
`,
}

var expectedSingleClusterBrokenMetric = map[string]string{
	"cilium_node_health_connectivity_latency_seconds": `# HELP cilium_node_health_connectivity_latency_seconds The histogram for last observed latency between the current Cilium agent and other Cilium nodes in seconds
# TYPE cilium_node_health_connectivity_latency_seconds histogram
cilium_node_health_connectivity_latency_seconds_sum{address_type="primary",protocol="http",source_cluster="default",source_node_name="kind-worker",type="endpoint"} 60
cilium_node_health_connectivity_latency_seconds_count{address_type="primary",protocol="http",source_cluster="default",source_node_name="kind-worker",type="endpoint"} 1
cilium_node_health_connectivity_latency_seconds_sum{address_type="primary",protocol="http",source_cluster="default",source_node_name="kind-worker",type="node"} 0.001653627
cilium_node_health_connectivity_latency_seconds_count{address_type="primary",protocol="http",source_cluster="default",source_node_name="kind-worker",type="node"} 1
cilium_node_health_connectivity_latency_seconds_sum{address_type="primary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",type="endpoint"} 60
cilium_node_health_connectivity_latency_seconds_count{address_type="primary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",type="endpoint"} 1
cilium_node_health_connectivity_latency_seconds_sum{address_type="primary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",type="node"} 0.007041796
cilium_node_health_connectivity_latency_seconds_count{address_type="primary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",type="node"} 1
cilium_node_health_connectivity_latency_seconds_sum{address_type="secondary",protocol="http",source_cluster="default",source_node_name="kind-worker",type="endpoint"} 0.005121015
cilium_node_health_connectivity_latency_seconds_count{address_type="secondary",protocol="http",source_cluster="default",source_node_name="kind-worker",type="endpoint"} 1
cilium_node_health_connectivity_latency_seconds_sum{address_type="secondary",protocol="http",source_cluster="default",source_node_name="kind-worker",type="node"} 60
cilium_node_health_connectivity_latency_seconds_count{address_type="secondary",protocol="http",source_cluster="default",source_node_name="kind-worker",type="node"} 1
cilium_node_health_connectivity_latency_seconds_sum{address_type="secondary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",type="endpoint"} 0.000672601
cilium_node_health_connectivity_latency_seconds_count{address_type="secondary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",type="endpoint"} 1
cilium_node_health_connectivity_latency_seconds_sum{address_type="secondary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",type="node"} 60
cilium_node_health_connectivity_latency_seconds_count{address_type="secondary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",type="node"} 1
`,
	"cilium_node_health_connectivity_status": `# HELP cilium_node_health_connectivity_status The number of endpoints with last observed status of both ICMP and HTTP connectivity between the current Cilium agent and other Cilium nodes
# TYPE cilium_node_health_connectivity_status gauge
cilium_node_health_connectivity_status{source_cluster="default",source_node_name="kind-worker",status="reachable",type="endpoint"} 1
cilium_node_health_connectivity_status{source_cluster="default",source_node_name="kind-worker",status="reachable",type="node"} 1
cilium_node_health_connectivity_status{source_cluster="default",source_node_name="kind-worker",status="unknown",type="endpoint"} 0
cilium_node_health_connectivity_status{source_cluster="default",source_node_name="kind-worker",status="unknown",type="node"} 0
cilium_node_health_connectivity_status{source_cluster="default",source_node_name="kind-worker",status="unreachable",type="endpoint"} 1
cilium_node_health_connectivity_status{source_cluster="default",source_node_name="kind-worker",status="unreachable",type="node"} 1
`,
}

func Test_server_getClusterNodeName(t *testing.T) {
	tests := []struct {
		name                string
		fullName            string
		expectedClusterName string
		expectedNodeName    string
	}{
		{
			name:                "no cluster name",
			fullName:            "k8s1",
			expectedClusterName: "default",
			expectedNodeName:    "k8s1",
		},
		{
			name:                "simple full name",
			fullName:            "kind-kind/worker",
			expectedClusterName: "kind-kind",
			expectedNodeName:    "worker",
		},
		{
			name:                "cluster name is having slash",
			fullName:            "arn:aws:eks:us-west-2:012345678910:cluster/cluster/name",
			expectedClusterName: "arn:aws:eks:us-west-2:012345678910:cluster/cluster",
			expectedNodeName:    "name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clusterName, nodeName := getClusterNodeName(tt.fullName)
			require.Equal(t, tt.expectedClusterName, clusterName)
			require.Equal(t, tt.expectedNodeName, nodeName)
		})
	}
}

func Test_server_collectNodeConnectivityMetrics(t *testing.T) {
	tests := []struct {
		name           string
		localStatus    *healthModels.SelfStatus
		connectivity   *healthReport
		metric         func() metric.WithMetadata
		expectedMetric string
		expectedCount  int
	}{
		{
			name: "single cluster for cilium_node_health_connectivity_status",
			localStatus: &healthModels.SelfStatus{
				Name: "kind-worker",
			},
			connectivity:   sampleSingleClusterConnectivity,
			metric:         func() metric.WithMetadata { return metrics.NodeHealthConnectivityStatus },
			expectedCount:  6,
			expectedMetric: expectedSingleClusterMetric["cilium_node_health_connectivity_status"],
		},
		{
			name: "single cluster for cilium_node_health_connectivity_latency_seconds",
			localStatus: &healthModels.SelfStatus{
				Name: "kind-worker",
			},
			connectivity:   sampleSingleClusterConnectivity,
			metric:         func() metric.WithMetadata { return metrics.NodeHealthConnectivityLatency },
			expectedCount:  8,
			expectedMetric: expectedSingleClusterMetric["cilium_node_health_connectivity_latency_seconds"],
		},
		{
			name: "cluster mesh for cilium_node_health_connectivity_status",
			localStatus: &healthModels.SelfStatus{
				Name: "kind-cilium-mesh-1/kind-cilium-mesh-1-worker",
			},
			connectivity:   sampleClustermeshConnectivity,
			metric:         func() metric.WithMetadata { return metrics.NodeHealthConnectivityStatus },
			expectedCount:  6,
			expectedMetric: expectedClustermeshMetric["cilium_node_health_connectivity_status"],
		},
		{
			name: "cluster mesh for cilium_node_health_connectivity_latency_seconds",
			localStatus: &healthModels.SelfStatus{
				Name: "kind-cilium-mesh-1/kind-cilium-mesh-1-worker",
			},
			connectivity:   sampleClustermeshConnectivity,
			metric:         func() metric.WithMetadata { return metrics.NodeHealthConnectivityLatency },
			expectedCount:  8,
			expectedMetric: expectedClustermeshMetric["cilium_node_health_connectivity_latency_seconds"],
		},
		{
			name: "single cluster broken for cilium_node_health_connectivity_status",
			localStatus: &healthModels.SelfStatus{
				Name: "kind-worker",
			},
			connectivity:   sampleSingleClusterConnectivityBroken,
			metric:         func() metric.WithMetadata { return metrics.NodeHealthConnectivityStatus },
			expectedCount:  6,
			expectedMetric: expectedSingleClusterBrokenMetric["cilium_node_health_connectivity_status"],
		},
		{
			name: "single cluster broken for cilium_node_health_connectivity_latency_seconds",
			localStatus: &healthModels.SelfStatus{
				Name: "kind-worker",
			},
			connectivity:   sampleSingleClusterConnectivityBroken,
			metric:         func() metric.WithMetadata { return metrics.NodeHealthConnectivityLatency },
			expectedCount:  8,
			expectedMetric: expectedSingleClusterBrokenMetric["cilium_node_health_connectivity_latency_seconds"],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics.NewLegacyMetrics()
			tt.metric().SetEnabled(true)
			collector := tt.metric().(prometheus.Collector)
			s := &Server{
				connectivity: tt.connectivity,
				localStatus:  tt.localStatus,
			}
			s.collectNodeConnectivityMetrics()

			// perform static checks such as prometheus naming convention, number of labels matching, etc
			lintProblems, err := testutil.CollectAndLint(collector)
			require.NoError(t, err)
			require.Empty(t, lintProblems)

			// check the number of metrics
			count := testutil.CollectAndCount(collector)
			require.Equal(t, tt.expectedCount, count)

			// compare the metric output
			metricName := "none"
			if strings.Contains(tt.name, latencyMetricName) {
				metricName = latencyMetricName
			} else if strings.Contains(tt.name, "cilium_node_health_connectivity_status") {
				metricName = statusMetricName
			}
			bytearr, err := testutil.CollectAndFormat(collector, expfmt.TypeTextPlain, metricName)
			require.NoError(t, err)
			scanner := bufio.NewScanner(strings.NewReader(string(bytearr)))
			var actualOutput strings.Builder
			// omit histogram buckets from comparison testing
			for scanner.Scan() {
				line := scanner.Text()
				if !strings.Contains(line, "bucket") {
					actualOutput.WriteString(line + "\n")
				}
			}
			require.Equal(t, tt.expectedMetric, actualOutput.String())
		})
	}
}
