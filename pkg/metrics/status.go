// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metrics

import (
	clientPkg "github.com/cilium/cilium/pkg/client"
	healthClientPkg "github.com/cilium/cilium/pkg/health/client"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

type statusCollector struct {
	ciliumClient *clientPkg.Client
	healthClient *healthClientPkg.Client

	controllersFailingDesc         *prometheus.Desc
	ipAddressesDesc                *prometheus.Desc
	unreachableNodesDesc           *prometheus.Desc
	unreachableHealthEndpointsDesc *prometheus.Desc
}

func newStatusCollector() *statusCollector {
	ciliumClient, err := clientPkg.NewClient("")
	if err != nil {
		log.WithError(err).Fatal("Error while creating Cilium API client")
	}

	healthClient, err := healthClientPkg.NewClient("")
	if err != nil {
		log.WithError(err).Fatal("Error while creating cilium-health API client")
	}

	return &statusCollector{
		ciliumClient: ciliumClient,
		healthClient: healthClient,
		controllersFailingDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "controllers_failing"),
			"Number of failing controllers",
			nil, nil,
		),
		ipAddressesDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "ip_addresses"),
			"Number of allocated IP addresses",
			[]string{"family"}, nil,
		),
		unreachableNodesDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "unreachable_nodes"),
			"Number of nodes that cannot be reached",
			nil, nil,
		),
		unreachableHealthEndpointsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "unreachable_health_endpoints"),
			"Number of health endpoints that cannot be reached",
			nil, nil,
		),
	}
}

func (s *statusCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- s.controllersFailingDesc
	ch <- s.ipAddressesDesc
	ch <- s.unreachableNodesDesc
	ch <- s.unreachableHealthEndpointsDesc
}

func (s *statusCollector) Collect(ch chan<- prometheus.Metric) {
	statusResponse, err := s.ciliumClient.Daemon.GetHealthz(nil)
	if err != nil {
		log.WithError(err).Error("Error while getting Cilium status")
		return
	}

	if statusResponse.Payload == nil {
		return
	}

	// Controllers failing
	controllersFailing := 0

	for _, ctrl := range statusResponse.Payload.Controllers {
		if ctrl.Status == nil {
			continue
		}
		if ctrl.Status.ConsecutiveFailureCount > 0 {
			controllersFailing++
		}
	}

	ch <- prometheus.MustNewConstMetric(
		s.controllersFailingDesc,
		prometheus.GaugeValue,
		float64(controllersFailing),
	)

	if statusResponse.Payload.Ipam != nil {
		// Address count
		ch <- prometheus.MustNewConstMetric(
			s.ipAddressesDesc,
			prometheus.GaugeValue,
			float64(len(statusResponse.Payload.Ipam.IPV4)),
			"ipv4",
		)

		ch <- prometheus.MustNewConstMetric(
			s.ipAddressesDesc,
			prometheus.GaugeValue,
			float64(len(statusResponse.Payload.Ipam.IPV6)),
			"ipv6",
		)
	}

	healthStatusResponse, err := s.healthClient.Connectivity.GetStatus(nil)
	if err != nil {
		log.WithError(err).Error("Error while getting cilium-health status")
		return
	}

	if healthStatusResponse.Payload == nil {
		return
	}

	// Nodes and endpoints healthStatusResponse
	var (
		unreachableNodes     int
		unreachableEndpoints int
	)

	for _, nodeStatus := range healthStatusResponse.Payload.Nodes {
		if !healthClientPkg.PathIsHealthy(healthClientPkg.GetHostPrimaryAddress(nodeStatus)) {
			unreachableNodes++
		}
		if nodeStatus.Endpoint != nil && !healthClientPkg.PathIsHealthy(nodeStatus.Endpoint) {
			unreachableEndpoints++
		}
	}

	ch <- prometheus.MustNewConstMetric(
		s.unreachableNodesDesc,
		prometheus.GaugeValue,
		float64(unreachableNodes),
	)

	ch <- prometheus.MustNewConstMetric(
		s.unreachableHealthEndpointsDesc,
		prometheus.GaugeValue,
		float64(unreachableEndpoints),
	)
}
