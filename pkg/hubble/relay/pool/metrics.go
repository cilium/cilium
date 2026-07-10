// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pool

import (
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/connectivity"

	"github.com/cilium/cilium/pkg/lock"
)

const (
	// namespace is a namespace used in Prometheus pool metrics naming
	namespace = "hubble_relay"

	// subsystem is a subsystem used in Prometheus pool metrics naming
	subsystem = "pool"

	// nilConnectionLabelValue is a value for "status" label for PeerConnStatus
	// metric, used for reporting peers that have nil connection
	// (no connectivity.State applies to these peers).
	nilConnectionLabelValue = "NIL_CONNECTION"
)

// PoolMetrics holds metrics related to the scope of this package.
type PoolMetrics struct {
	PeerConnStatus   *prometheus.GaugeVec
	peerConnStatusMu lock.Mutex
}

// NewPoolMetrics creates a new PoolMetrics object.
func NewPoolMetrics(registry prometheus.Registerer) *PoolMetrics {
	m := &PoolMetrics{
		PeerConnStatus: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "peer_connection_status",
			Help:      "Measures the connectivity status of all peers by counting the number of peers for each given connection status.",
		}, []string{"status"}),
	}
	registry.MustRegister(m.PeerConnStatus)
	return m
}

// ObservePeerConnectionStatus sets the value of PeerConnStatus gauge metric family.
// This method is thread-safe.
func (m *PoolMetrics) ObservePeerConnectionStatus(peerConnStatus map[connectivity.State]uint32, nilConnNum uint32) {
	// initialize map with zeros to make sure gauges are set even if caller does not pass values for every key
	status := map[string]uint32{
		connectivity.Idle.String():             0,
		connectivity.Connecting.String():       0,
		connectivity.Ready.String():            0,
		connectivity.TransientFailure.String(): 0,
		connectivity.Shutdown.String():         0,
		nilConnectionLabelValue:                0,
	}

	status[nilConnectionLabelValue] = nilConnNum
	for state, num := range peerConnStatus {
		status[state.String()] = num
	}

	m.peerConnStatusMu.Lock()
	for state, num := range status {
		m.PeerConnStatus.WithLabelValues(state).Set(float64(num))
	}
	m.peerConnStatusMu.Unlock()
}
