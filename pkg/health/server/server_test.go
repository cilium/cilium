// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"strings"

	. "github.com/cilium/checkmate"
	"github.com/prometheus/client_golang/prometheus/testutil"

	healthModels "github.com/cilium/cilium/api/v1/health/models"
	"github.com/cilium/cilium/pkg/metrics"
)

type ServerTestSuite struct{}

var _ = Suite(&ServerTestSuite{})

var sampleSingleClusterConnectivity = &healthReport{
	nodes: []*healthModels.NodeStatus{
		{
			HealthEndpoint: &healthModels.EndpointStatus{
				PrimaryAddress: &healthModels.PathStatus{
					HTTP: &healthModels.ConnectivityStatus{
						Latency: 212100,
					},
					Icmp: &healthModels.ConnectivityStatus{
						Latency: 672600,
					},
					IP: "10.244.3.219",
				},
				SecondaryAddresses: []*healthModels.PathStatus{
					{
						HTTP: &healthModels.ConnectivityStatus{
							Latency: 212101,
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
						Latency: 165362,
					},
					Icmp: &healthModels.ConnectivityStatus{
						Latency: 704179,
					},
					IP: "172.18.0.3",
				},
				SecondaryAddresses: []*healthModels.PathStatus{
					{
						HTTP: &healthModels.ConnectivityStatus{
							Latency: 212102,
						},
						Icmp: &healthModels.ConnectivityStatus{
							Latency: 672602,
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
						Latency: 312100,
					},
					Icmp: &healthModels.ConnectivityStatus{
						Latency: 772600,
					},
					IP: "10.244.3.219",
				},
				SecondaryAddresses: []*healthModels.PathStatus{
					{
						HTTP: &healthModels.ConnectivityStatus{
							Latency: 312101,
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
						Latency: 704179,
					},
					IP: "172.18.0.1",
				},
				SecondaryAddresses: []*healthModels.PathStatus{
					{
						HTTP: &healthModels.ConnectivityStatus{
							Latency: 312105,
						},
						Icmp: &healthModels.ConnectivityStatus{
							Latency: 772606,
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
						Latency: 583711,
					},
					IP: "10.1.2.143",
				},
				SecondaryAddresses: []*healthModels.PathStatus{
					{
						HTTP: &healthModels.ConnectivityStatus{
							Latency: 212101,
						},
						Icmp: &healthModels.ConnectivityStatus{
							Latency: 672601,
						},
						IP: "10.1.2.144",
					},
				},
			},
			Host: &healthModels.HostStatus{
				PrimaryAddress: &healthModels.PathStatus{
					HTTP: &healthModels.ConnectivityStatus{
						Latency: 166101,
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
							Latency: 672603,
						},
						IP: "172.18.0.4",
					},
				},
			},
			Name: "kind-cilium-mesh-2/kind-cilium-mesh-2-worker",
		},
	},
}

var expectedSingleClusterMetric = map[string]string{
	"cilium_node_connectivity_latency_seconds": `
# HELP cilium_node_connectivity_latency_seconds The last observed latency between the current Cilium agent and other Cilium nodes in seconds
# TYPE cilium_node_connectivity_latency_seconds gauge
cilium_node_connectivity_latency_seconds{address_type="primary",protocol="http",source_cluster="default",source_node_name="kind-worker",target_cluster="default",target_node_ip="10.244.3.219",target_node_name="kind-worker",target_node_type="local_node",type="endpoint"} 0.0002121
cilium_node_connectivity_latency_seconds{address_type="primary",protocol="http",source_cluster="default",source_node_name="kind-worker",target_cluster="default",target_node_ip="172.18.0.3",target_node_name="kind-worker",target_node_type="local_node",type="node"} 0.000165362
cilium_node_connectivity_latency_seconds{address_type="primary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",target_cluster="default",target_node_ip="10.244.3.219",target_node_name="kind-worker",target_node_type="local_node",type="endpoint"} 0.0006726
cilium_node_connectivity_latency_seconds{address_type="primary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",target_cluster="default",target_node_ip="172.18.0.3",target_node_name="kind-worker",target_node_type="local_node",type="node"} 0.000704179
cilium_node_connectivity_latency_seconds{address_type="secondary",protocol="http",source_cluster="default",source_node_name="kind-worker",target_cluster="default",target_node_ip="10.244.3.220",target_node_name="kind-worker",target_node_type="local_node",type="endpoint"} 0.000212101
cilium_node_connectivity_latency_seconds{address_type="secondary",protocol="http",source_cluster="default",source_node_name="kind-worker",target_cluster="default",target_node_ip="172.18.0.4",target_node_name="kind-worker",target_node_type="local_node",type="node"} 0.000212102
cilium_node_connectivity_latency_seconds{address_type="secondary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",target_cluster="default",target_node_ip="10.244.3.220",target_node_name="kind-worker",target_node_type="local_node",type="endpoint"} 0.000672601
cilium_node_connectivity_latency_seconds{address_type="secondary",protocol="icmp",source_cluster="default",source_node_name="kind-worker",target_cluster="default",target_node_ip="172.18.0.4",target_node_name="kind-worker",target_node_type="local_node",type="node"} 0.000672602
`,
	"cilium_node_connectivity_status": `
# HELP cilium_node_connectivity_status The last observed status of both ICMP and HTTP connectivity between the current Cilium agent and other Cilium nodes
# TYPE cilium_node_connectivity_status gauge
cilium_node_connectivity_status{source_cluster="default",source_node_name="kind-worker",target_cluster="default",target_node_name="kind-worker",target_node_type="local_node",type="endpoint"} 1
cilium_node_connectivity_status{source_cluster="default",source_node_name="kind-worker",target_cluster="default",target_node_name="kind-worker",target_node_type="local_node",type="node"} 1
`,
}

var expectedClustermeshMetric = map[string]string{
	"cilium_node_connectivity_latency_seconds": `
# HELP cilium_node_connectivity_latency_seconds The last observed latency between the current Cilium agent and other Cilium nodes in seconds
# TYPE cilium_node_connectivity_latency_seconds gauge
cilium_node_connectivity_latency_seconds{address_type="primary",protocol="http",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-1",target_node_ip="10.244.3.219",target_node_name="kind-cilium-mesh-1-worker",target_node_type="local_node",type="endpoint"} 0.0003121
cilium_node_connectivity_latency_seconds{address_type="primary",protocol="http",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-1",target_node_ip="172.18.0.1",target_node_name="kind-cilium-mesh-1-worker",target_node_type="local_node",type="node"} 0.000165362
cilium_node_connectivity_latency_seconds{address_type="primary",protocol="http",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-2",target_node_ip="10.1.2.143",target_node_name="kind-cilium-mesh-2-worker",target_node_type="remote_inter_cluster",type="endpoint"} 0.000274815
cilium_node_connectivity_latency_seconds{address_type="primary",protocol="http",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-2",target_node_ip="172.18.0.3",target_node_name="kind-cilium-mesh-2-worker",target_node_type="remote_inter_cluster",type="node"} 0.000166101
cilium_node_connectivity_latency_seconds{address_type="primary",protocol="icmp",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-1",target_node_ip="10.244.3.219",target_node_name="kind-cilium-mesh-1-worker",target_node_type="local_node",type="endpoint"} 0.0007726
cilium_node_connectivity_latency_seconds{address_type="primary",protocol="icmp",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-1",target_node_ip="172.18.0.1",target_node_name="kind-cilium-mesh-1-worker",target_node_type="local_node",type="node"} 0.000704179
cilium_node_connectivity_latency_seconds{address_type="primary",protocol="icmp",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-2",target_node_ip="10.1.2.143",target_node_name="kind-cilium-mesh-2-worker",target_node_type="remote_inter_cluster",type="endpoint"} 0.000583711
cilium_node_connectivity_latency_seconds{address_type="primary",protocol="icmp",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-2",target_node_ip="172.18.0.3",target_node_name="kind-cilium-mesh-2-worker",target_node_type="remote_inter_cluster",type="node"} 0.000635688
cilium_node_connectivity_latency_seconds{address_type="secondary",protocol="http",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-1",target_node_ip="10.244.3.220",target_node_name="kind-cilium-mesh-1-worker",target_node_type="local_node",type="endpoint"} 0.000312101
cilium_node_connectivity_latency_seconds{address_type="secondary",protocol="http",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-1",target_node_ip="172.18.0.2",target_node_name="kind-cilium-mesh-1-worker",target_node_type="local_node",type="node"} 0.000312105
cilium_node_connectivity_latency_seconds{address_type="secondary",protocol="http",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-2",target_node_ip="10.1.2.144",target_node_name="kind-cilium-mesh-2-worker",target_node_type="remote_inter_cluster",type="endpoint"} 0.000212101
cilium_node_connectivity_latency_seconds{address_type="secondary",protocol="http",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-2",target_node_ip="172.18.0.4",target_node_name="kind-cilium-mesh-2-worker",target_node_type="remote_inter_cluster",type="node"} 0.000212103
cilium_node_connectivity_latency_seconds{address_type="secondary",protocol="icmp",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-1",target_node_ip="10.244.3.220",target_node_name="kind-cilium-mesh-1-worker",target_node_type="local_node",type="endpoint"} 0.000772601
cilium_node_connectivity_latency_seconds{address_type="secondary",protocol="icmp",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-1",target_node_ip="172.18.0.2",target_node_name="kind-cilium-mesh-1-worker",target_node_type="local_node",type="node"} 0.000772606
cilium_node_connectivity_latency_seconds{address_type="secondary",protocol="icmp",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-2",target_node_ip="10.1.2.144",target_node_name="kind-cilium-mesh-2-worker",target_node_type="remote_inter_cluster",type="endpoint"} 0.000672601
cilium_node_connectivity_latency_seconds{address_type="secondary",protocol="icmp",source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-2",target_node_ip="172.18.0.4",target_node_name="kind-cilium-mesh-2-worker",target_node_type="remote_inter_cluster",type="node"} 0.000672603
`,
	"cilium_node_connectivity_status": `
# HELP cilium_node_connectivity_status The last observed status of both ICMP and HTTP connectivity between the current Cilium agent and other Cilium nodes
# TYPE cilium_node_connectivity_status gauge
cilium_node_connectivity_status{source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-1",target_node_name="kind-cilium-mesh-1-worker",target_node_type="local_node",type="endpoint"} 1
cilium_node_connectivity_status{source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-1",target_node_name="kind-cilium-mesh-1-worker",target_node_type="local_node",type="node"} 1
cilium_node_connectivity_status{source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-2",target_node_name="kind-cilium-mesh-2-worker",target_node_type="remote_inter_cluster",type="endpoint"} 1
cilium_node_connectivity_status{source_cluster="kind-cilium-mesh-1",source_node_name="kind-cilium-mesh-1-worker",target_cluster="kind-cilium-mesh-2",target_node_name="kind-cilium-mesh-2-worker",target_node_type="remote_inter_cluster",type="node"} 1
`,
}

func (s *ServerTestSuite) Test_server_getClusterNodeName(c *C) {
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
		c.Log("Test :", tt.name)
		clusterName, nodeName := getClusterNodeName(tt.fullName)
		c.Assert(clusterName, Equals, tt.expectedClusterName)
		c.Assert(nodeName, Equals, tt.expectedNodeName)
	}
}

func (s *ServerTestSuite) Test_server_collectNodeConnectivityMetrics(c *C) {
	tests := []struct {
		name           string
		localStatus    *healthModels.SelfStatus
		connectivity   *healthReport
		metricName     string
		expectedMetric string
		expectedCount  int
	}{
		{
			name: "single cluster for cilium_node_connectivity_status",
			localStatus: &healthModels.SelfStatus{
				Name: "kind-worker",
			},
			connectivity:   sampleSingleClusterConnectivity,
			metricName:     "cilium_node_connectivity_status",
			expectedCount:  2,
			expectedMetric: expectedSingleClusterMetric["cilium_node_connectivity_status"],
		},
		{
			name: "single cluster for cilium_node_connectivity_latency_seconds",
			localStatus: &healthModels.SelfStatus{
				Name: "kind-worker",
			},
			connectivity:   sampleSingleClusterConnectivity,
			metricName:     "cilium_node_connectivity_latency_seconds",
			expectedCount:  8,
			expectedMetric: expectedSingleClusterMetric["cilium_node_connectivity_latency_seconds"],
		},
		{
			name: "cluster mesh for cilium_node_connectivity_status",
			localStatus: &healthModels.SelfStatus{
				Name: "kind-cilium-mesh-1/kind-cilium-mesh-1-worker",
			},
			connectivity:   sampleClustermeshConnectivity,
			metricName:     "cilium_node_connectivity_status",
			expectedCount:  4,
			expectedMetric: expectedClustermeshMetric["cilium_node_connectivity_status"],
		},
		{
			name: "cluster mesh for cilium_node_connectivity_latency_seconds",
			localStatus: &healthModels.SelfStatus{
				Name: "kind-cilium-mesh-1/kind-cilium-mesh-1-worker",
			},
			connectivity:   sampleClustermeshConnectivity,
			metricName:     "cilium_node_connectivity_latency_seconds",
			expectedCount:  16,
			expectedMetric: expectedClustermeshMetric["cilium_node_connectivity_latency_seconds"],
		},
	}

	for _, tt := range tests {
		c.Log("Test :", tt.name)

		_, collectors := metrics.CreateConfiguration([]string{tt.metricName})
		s := &Server{
			connectivity: tt.connectivity,
			localStatus:  tt.localStatus,
		}
		s.collectNodeConnectivityMetrics()

		// perform static checks such as prometheus naming convention, number of labels matching, etc
		lintProblems, err := testutil.CollectAndLint(collectors[0])
		c.Assert(err, IsNil)
		c.Assert(lintProblems, HasLen, 0)

		// check the number of metrics
		count := testutil.CollectAndCount(collectors[0])
		c.Assert(count, Equals, tt.expectedCount)

		// compare the metric output
		err = testutil.CollectAndCompare(collectors[0], strings.NewReader(tt.expectedMetric))
		c.Assert(err, IsNil)
	}

}
