// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	labelErrorType         = "type"
	labelErrorTypeInbound  = "inbound"
	labelErrorTypeOutbound = "outbound"

	labelErrorOther            = "other"
	labelErrorNoBuffer         = "no_buffer"
	labelErrorHeader           = "header"
	labelErrorNoState          = "no_state"
	labelErrorStateProtocol    = "state_protocol"
	labelErrorStateMode        = "state_mode"
	labelErrorStateSequence    = "state_sequence"
	labelErrorStateExpired     = "state_expired"
	labelErrorStateMismatched  = "state_mismatched"
	labelErrorStateInvalid     = "state_invalid"
	labelErrorTemplateMismatch = "template_mismatched"
	labelErrorNoPolicy         = "no_policy"
	labelErrorPolicyBlocked    = "policy_blocked"
	labelErrorPolicyDead       = "policy_dead"
	labelErrorPolicy           = "policy"
	labelErrorForwardHeader    = "forward_header"
	labelErrorAcquire          = "acquire"
	labelErrorBundleGeneration = "bundle_generation"
	labelErrorBundleCheck      = "bundle_check"
)

type Metrics struct {
	XfrmCollector *XfrmCollector
}

func NewIPSecMetrics() *Metrics {
	return &Metrics{
		XfrmCollector: newXFRMCollector(procfs.NewXfrmStat),
	}
}

type XfrmCollector struct {
	xfrmStatFunc func() (procfs.XfrmStat, error)

	// Inbound errors
	xfrmErrorDesc *prometheus.Desc
	Enabled       bool
}

// newXFRMCollector returns a new prometheus.Collector for /proc/net/xfrm_stat
// https://www.kernel.org/doc/Documentation/networking/xfrm_proc.txt
func newXFRMCollector(statFn func() (procfs.XfrmStat, error)) *XfrmCollector {
	return &XfrmCollector{
		xfrmStatFunc: statFn,

		xfrmErrorDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, subsystem, "xfrm_error"),
			"Total number of xfrm errors",
			[]string{labelErrorType, metrics.LabelError}, nil,
		),
	}
}

func (x *XfrmCollector) Describe(ch chan<- *prometheus.Desc) {
	if !x.Enabled {
		return
	}

	ch <- x.xfrmErrorDesc
}

func (x *XfrmCollector) Collect(ch chan<- prometheus.Metric) {
	if !x.Enabled {
		return
	}

	stats, err := x.xfrmStatFunc()
	if err != nil {
		log.WithError(err).Error("Error while getting xfrm stats")
		return
	}

	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmInError), labelErrorTypeInbound, labelErrorOther)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmInBufferError), labelErrorTypeInbound, labelErrorNoBuffer)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmInHdrError), labelErrorTypeInbound, labelErrorHeader)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmInNoStates), labelErrorTypeInbound, labelErrorNoState)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmInStateProtoError), labelErrorTypeInbound, labelErrorStateProtocol)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmInStateModeError), labelErrorTypeInbound, labelErrorStateMode)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmInStateSeqError), labelErrorTypeInbound, labelErrorStateSequence)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmInStateExpired), labelErrorTypeInbound, labelErrorStateExpired)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmInStateMismatch), labelErrorTypeInbound, labelErrorStateMismatched)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmInStateInvalid), labelErrorTypeInbound, labelErrorStateInvalid)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmInTmplMismatch), labelErrorTypeInbound, labelErrorTemplateMismatch)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmInNoPols), labelErrorTypeInbound, labelErrorNoPolicy)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmInPolBlock), labelErrorTypeInbound, labelErrorPolicyBlocked)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmInPolError), labelErrorTypeInbound, labelErrorPolicy)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmFwdHdrError), labelErrorTypeInbound, labelErrorForwardHeader)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmAcquireError), labelErrorTypeInbound, labelErrorAcquire)

	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmOutError), labelErrorTypeOutbound, labelErrorOther)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmOutBundleGenError), labelErrorTypeOutbound, labelErrorBundleGeneration)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmOutBundleCheckError), labelErrorTypeOutbound, labelErrorBundleCheck)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmOutNoStates), labelErrorTypeOutbound, labelErrorNoState)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmOutStateProtoError), labelErrorTypeOutbound, labelErrorStateProtocol)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmOutStateModeError), labelErrorTypeOutbound, labelErrorStateMode)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmOutStateSeqError), labelErrorTypeOutbound, labelErrorStateSequence)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmOutStateExpired), labelErrorTypeOutbound, labelErrorStateExpired)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmOutPolBlock), labelErrorTypeOutbound, labelErrorPolicyBlocked)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmOutPolDead), labelErrorTypeOutbound, labelErrorPolicyDead)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmOutPolError), labelErrorTypeOutbound, labelErrorPolicy)
	ch <- prometheus.MustNewConstMetric(x.xfrmErrorDesc, prometheus.GaugeValue, float64(stats.XfrmOutStateInvalid), labelErrorTypeOutbound, labelErrorStateInvalid)

}

func (x *XfrmCollector) IsEnabled() bool {
	return x.Enabled
}

func (x *XfrmCollector) SetEnabled(enabled bool) {
	x.Enabled = enabled
}

func (x *XfrmCollector) Opts() metric.Opts {
	return metric.Opts{
		ConfigName: prometheus.BuildFQName(metrics.Namespace, subsystem, "xfrm_error"),
		Namespace:  metrics.Namespace,
		Subsystem:  subsystem,
		Name:       "xfrm_error",
		Disabled:   !x.Enabled,
	}
}
