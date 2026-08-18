// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	subsystem            = "xds"
	typeURLLabel         = "type_url"
	statusLabel          = "status"
	statusACKValue       = "ack"
	statusNACKValue      = "nack"
	statusCancelValue    = "cancel"
	modeLabel            = "mode"
	operationLabel       = "operation"
	resourceActionLabel  = "resource_action"
	resourceUpdatedValue = "updated"
	resourceRemovedValue = "removed"
)

type Metrics interface {
	IncreaseNACK(string)
	IncreaseACK(string)
	IncreaseCancel(string)
}

// Telemetry is the optional, mode-aware xDS instrumentation implemented by
// XDSMetrics. Keeping it separate from Metrics preserves lightweight test
// implementations that only care about ACK/NACK accounting.
type Telemetry interface {
	ObserveUpdate(mode, operation string, duration time.Duration)
	ObserveSnapshotGeneration(mode string, duration time.Duration)
	ObserveResponse(mode, typeURL string, size, updated, removed int)
	ObserveAcknowledgement(mode, typeURL, status string, duration time.Duration)
	IncreaseStream(mode string)
	DecreaseStream(mode string)
}

var _ Metrics = (*XDSMetrics)(nil)

type XDSMetrics struct {
	// EventCount is the number of ACK and NACK responses from envoy.
	EventCount metric.Vec[metric.Counter]

	UpdateDuration             metric.Vec[metric.Observer]
	SnapshotGenerationDuration metric.Vec[metric.Observer]
	ResponseSize               metric.Vec[metric.Observer]
	ResponseResources          metric.Vec[metric.Counter]
	Acknowledgements           metric.Vec[metric.Counter]
	AcknowledgementDuration    metric.Vec[metric.Observer]
	StreamsActive              metric.Vec[metric.Gauge]
}

func NewXDSMetric() *XDSMetrics {
	return &XDSMetrics{
		EventCount: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "events_count",
			Help:      "The number of ACK/NACK/Cancel event responses from Envoy",
		}, []string{typeURLLabel, statusLabel}),
		UpdateDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "update_duration_seconds",
			Help:      "Time spent applying an xDS resource update to the server cache",
			Buckets:   prometheus.ExponentialBuckets(0.00001, 10, 7),
		}, []string{modeLabel, operationLabel}),
		SnapshotGenerationDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "snapshot_generation_duration_seconds",
			Help:      "Time spent generating an ADS snapshot",
			Buckets:   prometheus.ExponentialBuckets(0.00001, 10, 7),
		}, []string{modeLabel}),
		ResponseSize: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "response_size_bytes",
			Help:      "Logical protobuf size of xDS responses",
			Buckets:   prometheus.ExponentialBuckets(128, 4, 9),
		}, []string{modeLabel, typeURLLabel}),
		ResponseResources: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "response_resources_total",
			Help:      "Number of resources included in xDS responses",
		}, []string{modeLabel, typeURLLabel, resourceActionLabel}),
		Acknowledgements: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "acknowledgements_total",
			Help:      "Number of xDS ACK and NACK responses from Envoy",
		}, []string{modeLabel, typeURLLabel, statusLabel}),
		AcknowledgementDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "acknowledgement_duration_seconds",
			Help:      "Time from sending an xDS response until its ACK or NACK",
			Buckets:   prometheus.ExponentialBuckets(0.00001, 10, 7),
		}, []string{modeLabel, typeURLLabel, statusLabel}),
		StreamsActive: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "streams_active",
			Help:      "Current number of active xDS streams",
		}, []string{modeLabel}),
	}
}

func (x *XDSMetrics) IncreaseNACK(typeURL string) {
	x.EventCount.WithLabelValues(typeURL, statusNACKValue).Inc()
}

func (x *XDSMetrics) IncreaseACK(typeURL string) {
	x.EventCount.WithLabelValues(typeURL, statusACKValue).Inc()
}

func (x *XDSMetrics) IncreaseCancel(typeURL string) {
	x.EventCount.WithLabelValues(typeURL, statusCancelValue).Inc()
}

func (x *XDSMetrics) ObserveUpdate(mode, operation string, duration time.Duration) {
	x.UpdateDuration.WithLabelValues(mode, operation).Observe(duration.Seconds())
}

func (x *XDSMetrics) ObserveSnapshotGeneration(mode string, duration time.Duration) {
	x.SnapshotGenerationDuration.WithLabelValues(mode).Observe(duration.Seconds())
}

func (x *XDSMetrics) ObserveResponse(mode, typeURL string, size, updated, removed int) {
	x.ResponseSize.WithLabelValues(mode, typeURL).Observe(float64(size))
	x.ResponseResources.WithLabelValues(mode, typeURL, resourceUpdatedValue).Add(float64(updated))
	x.ResponseResources.WithLabelValues(mode, typeURL, resourceRemovedValue).Add(float64(removed))
}

func (x *XDSMetrics) ObserveAcknowledgement(mode, typeURL, status string, duration time.Duration) {
	x.Acknowledgements.WithLabelValues(mode, typeURL, status).Inc()
	x.AcknowledgementDuration.WithLabelValues(mode, typeURL, status).Observe(duration.Seconds())
}

func (x *XDSMetrics) IncreaseStream(mode string) {
	x.StreamsActive.WithLabelValues(mode).Inc()
}

func (x *XDSMetrics) DecreaseStream(mode string) {
	x.StreamsActive.WithLabelValues(mode).Dec()
}

func ObserveUpdate(metrics Metrics, mode, operation string, duration time.Duration) {
	if telemetry, ok := metrics.(Telemetry); ok {
		telemetry.ObserveUpdate(mode, operation, duration)
	}
}

func ObserveSnapshotGeneration(metrics Metrics, mode string, duration time.Duration) {
	if telemetry, ok := metrics.(Telemetry); ok {
		telemetry.ObserveSnapshotGeneration(mode, duration)
	}
}

func ObserveResponse(metrics Metrics, mode, typeURL string, size, updated, removed int) {
	if telemetry, ok := metrics.(Telemetry); ok {
		telemetry.ObserveResponse(mode, typeURL, size, updated, removed)
	}
}

func ObserveAcknowledgement(metrics Metrics, mode, typeURL string, nack bool, duration time.Duration) {
	if telemetry, ok := metrics.(Telemetry); ok {
		status := statusACKValue
		if nack {
			status = statusNACKValue
		}
		telemetry.ObserveAcknowledgement(mode, typeURL, status, duration)
	}
}

func IncreaseStream(metrics Metrics, mode string) {
	if telemetry, ok := metrics.(Telemetry); ok {
		telemetry.IncreaseStream(mode)
	}
}

func DecreaseStream(metrics Metrics, mode string) {
	if telemetry, ok := metrics.(Telemetry); ok {
		telemetry.DecreaseStream(mode)
	}
}
