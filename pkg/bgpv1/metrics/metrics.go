// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"context"
	"log/slog"
	"net/netip"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

type collector struct {
	SessionState          *prometheus.Desc
	TotalAdvertisedRoutes *prometheus.Desc
	TotalReceivedRoutes   *prometheus.Desc

	in collectorIn
}

type collectorIn struct {
	cell.In

	Logger        *slog.Logger
	DaemonConfig  *option.DaemonConfig
	Registry      *metrics.Registry
	RouterManager agent.BGPRouterManager
}

// RegisterCollector registers the BGP Control Plane metrics collector to the
// global prometheus registry. We don't rely on the metrics.Metric because the
// collectors we can provide through metrics.Metric needs to implement
// prometheus.Collector per metric which is not optimal in our case. We can
// retrieve the multiple metrics from the single call to
// RouterManager.GetPeers() and it is wasteful to call the same function
// multiple times for each metric. Thus, we provide a raw Collector through
// MustRegister interface. We may want to revisit this in the future.
func RegisterCollector(in collectorIn) {
	// Don't provide the collector if BGP control plane is disabled
	if !in.DaemonConfig.EnableBGPControlPlane {
		return
	}
	in.Registry.MustRegister(&collector{
		SessionState: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, types.MetricsSubsystem, "session_state"),
			"Current state of the BGP session with the peer, Up = 1 or Down = 0",
			[]string{types.LabelVRouter, types.LabelNeighbor, types.LabelNeighborAsn}, nil,
		),
		TotalAdvertisedRoutes: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, types.MetricsSubsystem, "advertised_routes"),
			"Number of routes advertised to the peer",
			[]string{types.LabelVRouter, types.LabelNeighbor, types.LabelNeighborAsn, types.LabelAfi, types.LabelSafi}, nil,
		),
		TotalReceivedRoutes: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, types.MetricsSubsystem, "received_routes"),
			"Number of routes received from the peer",
			[]string{types.LabelVRouter, types.LabelNeighbor, types.LabelNeighborAsn, types.LabelAfi, types.LabelSafi}, nil,
		),
		in: in,
	})
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.SessionState
	ch <- c.TotalAdvertisedRoutes
	ch <- c.TotalReceivedRoutes
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	// We defensively set a 5 sec timeout here. When the underlying router
	// is not responsive, we cannot make a progress. 5 sec is chosen to be
	// a too long time that we should never hit for normal cases. We should
	// revisit this timeout when the metrics collection starts to involve a
	// network communication.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	peers, err := c.in.RouterManager.GetPeers(ctx)
	cancel()
	if err != nil {
		c.in.Logger.Error("Failed to retrieve BGP peer information. Metrics is not collected.", logfields.Error, err)
		return
	}

	for _, peer := range peers {
		if peer == nil {
			continue
		}

		vrouterLabel := strconv.FormatInt(peer.LocalAsn, 10)

		addr, err := netip.ParseAddr(peer.PeerAddress)
		if err != nil {
			continue
		}

		neighborLabel := netip.AddrPortFrom(addr, uint16(peer.PeerPort)).String()
		neighborAsnLabel := strconv.FormatInt(peer.PeerAsn, 10)

		// Collect session state metrics
		var up float64
		if peer.SessionState == types.SessionEstablished.String() {
			up = 1
		} else {
			up = 0
		}
		ch <- prometheus.MustNewConstMetric(
			c.SessionState,
			prometheus.GaugeValue,
			up,
			vrouterLabel,
			neighborLabel,
			neighborAsnLabel,
		)

		// Collect route metrics per address family
		for _, family := range peer.Families {
			if family == nil {
				continue
			}
			ch <- prometheus.MustNewConstMetric(
				c.TotalAdvertisedRoutes,
				prometheus.GaugeValue,
				float64(family.Advertised),
				vrouterLabel,
				neighborLabel,
				neighborAsnLabel,
				family.Afi,
				family.Safi,
			)
			ch <- prometheus.MustNewConstMetric(
				c.TotalReceivedRoutes,
				prometheus.GaugeValue,
				float64(family.Received),
				vrouterLabel,
				neighborLabel,
				neighborAsnLabel,
				family.Afi,
				family.Safi,
			)
		}
	}
}
