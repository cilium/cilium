// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"context"
	"log/slog"
	"net/netip"
	"reflect"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bgp/agent"
	bgpmock "github.com/cilium/cilium/pkg/bgp/mock"
	"github.com/cilium/cilium/pkg/bgp/types"
)

func TestCollectBFDMetrics(t *testing.T) {
	manager := &bgpmock.MockBGPRouterManager{
		GetPeers_: func(context.Context, *agent.GetPeersRequest) (*agent.GetPeersResponse, error) {
			return &agent.GetPeersResponse{Instances: []agent.InstancePeerStates{{
				Name: "instance-a",
				Peers: []types.PeerState{{
					Address:      netip.MustParseAddr("192.0.2.1"),
					Port:         179,
					LocalAsn:     65000,
					PeerAsn:      65001,
					SessionState: types.SessionEstablished,
					BFD: &types.BFDState{
						SessionState: types.BFDSessionUp,
						ControlCounters: types.BFDPacketCounters{
							TransmittedPackets: 100,
							ReceivedPackets:    90,
						},
					},
				}},
			}}}, nil
		},
	}

	c := newTestCollector(manager)
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(c)

	families, err := registry.Gather()
	require.NoError(t, err)

	requireMetricValue(t, families, "cilium_bgp_control_plane_bfd_session_state", map[string]string{
		"instance_name": "instance-a", "local_asn": "65000", "neighbor": "192.0.2.1:179", "neighbor_asn": "65001",
	}, 1)
}

func newTestCollector(manager agent.BGPRouterManager) *collector {
	labels := []string{types.LabelName, types.LabelLocalAsn, types.LabelNeighbor, types.LabelNeighborAsn}
	return &collector{
		SessionState:          prometheus.NewDesc("cilium_bgp_control_plane_session_state", "", labels, nil),
		BFDSessionState:       prometheus.NewDesc("cilium_bgp_control_plane_bfd_session_state", "", labels, nil),
		TotalAdvertisedRoutes: prometheus.NewDesc("cilium_bgp_control_plane_advertised_routes", "", append(labels, types.LabelAfi, types.LabelSafi), nil),
		TotalReceivedRoutes:   prometheus.NewDesc("cilium_bgp_control_plane_received_routes", "", append(labels, types.LabelAfi, types.LabelSafi), nil),
		in:                    collectorIn{Logger: slog.Default(), RouterManager: manager},
	}
}

func requireMetricValue(t *testing.T, families []*dto.MetricFamily, name string, labels map[string]string, expected float64) {
	t.Helper()
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			actualLabels := make(map[string]string, len(metric.Label))
			for _, label := range metric.Label {
				actualLabels[label.GetName()] = label.GetValue()
			}
			if reflect.DeepEqual(labels, actualLabels) {
				require.Equal(t, expected, metric.GetGauge().GetValue())
				return
			}
		}
	}
	require.Failf(t, "metric not found", "metric %s with labels %v", name, labels)
}
