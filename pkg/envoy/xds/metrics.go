// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	subsystem       = "xds"
	typeURLLabel    = "type_url"
	statusLabel     = "status"
	statusACKValue  = "ack"
	statusNACKValue = "nack"
)

type Metrics interface {
	IncreaseNACK(string)
	IncreaseACK(string)
}

var _ Metrics = (*XDSMetrics)(nil)

type XDSMetrics struct {
	// EventCount is the number of ACK and NACK responses from envoy.
	EventCount metric.Vec[metric.Counter]
}

func NewXDSMetric() *XDSMetrics {
	return &XDSMetrics{
		EventCount: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "events_count",
			Help:      "The number of ACK/NACK event responses from Envoy",
		}, []string{typeURLLabel, statusLabel}),
	}
}

func (x *XDSMetrics) IncreaseNACK(typeURL string) {
	x.EventCount.WithLabelValues(typeURL, statusNACKValue).Inc()
}

func (x *XDSMetrics) IncreaseACK(typeURL string) {
	x.EventCount.WithLabelValues(typeURL, statusACKValue).Inc()
}
