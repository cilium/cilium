// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	clientPkg "github.com/cilium/cilium/pkg/client"
	healthClientPkg "github.com/cilium/cilium/pkg/health/client"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

type statusCollector struct {
	logger                   *slog.Logger
	daemonHealthGetter       daemonHealthGetter
	connectivityStatusGetter connectivityStatusGetter

	controllersFailingDesc         *prometheus.Desc
	ipAddressesDesc                *prometheus.Desc
	unreachableNodesDesc           *prometheus.Desc
	unreachableHealthEndpointsDesc *prometheus.Desc
}

func newStatusCollector(logger *slog.Logger) *statusCollector {
	ciliumClient, err := clientPkg.NewClient("")
	if err != nil {
		logging.Fatal(logger, "Error while creating Cilium API client", logfields.Error, err)
	}

	if option.Config.EnableHealthChecking {
		healthClient, err := healthClientPkg.NewClient("")
		if err != nil {
			logging.Fatal(logger, "Error while creating cilium-health API client", logfields.Error, err)
		}
		return newStatusCollectorWithClients(logger, ciliumClient.Daemon, healthClient.Connectivity)
	}

	return newStatusCollectorWithClients(logger, ciliumClient.Daemon, nil)
}

// newStatusCollectorWithClients provides a constructor with injected clients
func newStatusCollectorWithClients(logger *slog.Logger, d daemonHealthGetter, c connectivityStatusGetter) *statusCollector {
	return &statusCollector{
		logger:                   logger,
		daemonHealthGetter:       d,
		connectivityStatusGetter: c,
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
	if s.connectivityStatusGetter != nil {
		ch <- s.unreachableNodesDesc
		ch <- s.unreachableHealthEndpointsDesc
	}
}

func (s *statusCollector) Collect(ch chan<- prometheus.Metric) {
	statusResponse, err := s.daemonHealthGetter.GetHealthz(nil)
	if err != nil {
		s.logger.Error("Error while getting Cilium status", logfields.Error, err)
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

	// Skip health metrics if health checking is disabled
	if s.connectivityStatusGetter == nil {
		return
	}

	healthStatusResponse, err := s.connectivityStatusGetter.GetStatus(nil)
	if err != nil {
		s.logger.Error("Error while getting cilium-health status", logfields.Error, err)
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
		for _, addr := range healthClientPkg.GetAllHostAddresses(nodeStatus) {
			if healthClientPkg.GetPathConnectivityStatusType(addr) == healthClientPkg.ConnStatusUnreachable {
				unreachableNodes++
				break
			}
		}

		for _, addr := range healthClientPkg.GetAllEndpointAddresses(nodeStatus) {
			if healthClientPkg.GetPathConnectivityStatusType(addr) == healthClientPkg.ConnStatusUnreachable {
				unreachableEndpoints++
				break
			}
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
