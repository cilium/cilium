// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"strings"

	. "github.com/cilium/checkmate"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/health/client/connectivity"
	healthModels "github.com/cilium/cilium/api/v1/health/models"
	"github.com/cilium/cilium/api/v1/models"
)

type StatusCollectorTest struct{}

var _ = Suite(&StatusCollectorTest{})

var sampleHealthResponse = &daemon.GetHealthzOK{
	Payload: &models.StatusResponse{
		Controllers: models.ControllerStatuses{
			{},
			{
				Status: &models.ControllerStatusStatus{
					ConsecutiveFailureCount: 2,
					FailureCount:            0,
				},
			},
		},
		Ipam: &models.IPAMStatus{
			IPV4: []string{"10.11.0.82", "10.11.0.249", "10.11.0.46"},
			IPV6: []string{"fd00::9d15", "fd00::f61a", "fd00::7712"},
		},
	},
}

var sampleSingleClusterConnectivityResponse = &connectivity.GetStatusOK{
	Payload: &healthModels.HealthStatusResponse{
		Local: &healthModels.SelfStatus{
			Name: "kind-worker",
		},
		Nodes: []*healthModels.NodeStatus{
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
						{
							HTTP: &healthModels.ConnectivityStatus{
								Latency: 212102,
							},
							Icmp: &healthModels.ConnectivityStatus{
								Latency: 672602,
							},
							IP: "10.244.3.221",
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
					SecondaryAddresses: nil,
				},
				Name: "kind-worker",
			},
		},
	},
}

const expectedStatusMetric = `
# HELP cilium_controllers_failing Number of failing controllers
# TYPE cilium_controllers_failing gauge
cilium_controllers_failing 1
# HELP cilium_ip_addresses Number of allocated IP addresses
# TYPE cilium_ip_addresses gauge
cilium_ip_addresses{family="ipv4"} 3
cilium_ip_addresses{family="ipv6"} 3
# HELP cilium_unreachable_health_endpoints Number of health endpoints that cannot be reached
# TYPE cilium_unreachable_health_endpoints gauge
cilium_unreachable_health_endpoints 0
# HELP cilium_unreachable_nodes Number of nodes that cannot be reached
# TYPE cilium_unreachable_nodes gauge
cilium_unreachable_nodes 0
`

type fakeDaemonClient struct {
	response *daemon.GetHealthzOK
}

type fakeConnectivityClient struct {
	response *connectivity.GetStatusOK
}

func (f *fakeConnectivityClient) GetStatus(params *connectivity.GetStatusParams, opts ...connectivity.ClientOption) (*connectivity.GetStatusOK, error) {
	return f.response, nil
}

func (f *fakeDaemonClient) GetHealthz(params *daemon.GetHealthzParams, opts ...daemon.ClientOption) (*daemon.GetHealthzOK, error) {
	return f.response, nil
}

func (s *StatusCollectorTest) Test_statusCollector_Collect(c *C) {
	tests := []struct {
		name                 string
		healthResponse       *daemon.GetHealthzOK
		connectivityResponse *connectivity.GetStatusOK
		expectedMetric       string
		expectedCount        int
	}{
		{
			name:                 "check status metrics",
			healthResponse:       sampleHealthResponse,
			connectivityResponse: sampleSingleClusterConnectivityResponse,
			expectedCount:        5,
			expectedMetric:       expectedStatusMetric,
		},
	}

	for _, tt := range tests {
		c.Log("Test :", tt.name)
		collector := newStatusCollectorWithClients(&fakeDaemonClient{
			response: tt.healthResponse,
		}, &fakeConnectivityClient{
			response: tt.connectivityResponse,
		})

		// perform static checks such as prometheus naming convention, number of labels matching, etc
		lintProblems, err := testutil.CollectAndLint(collector)
		c.Assert(err, IsNil)
		c.Assert(lintProblems, HasLen, 0)

		// check the number of metrics
		count := testutil.CollectAndCount(collector)
		c.Assert(count, Equals, tt.expectedCount)

		// compare the metric output
		err = testutil.CollectAndCompare(collector, strings.NewReader(tt.expectedMetric))
		c.Assert(err, IsNil)
	}

}
