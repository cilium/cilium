// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/common/ipsec"
	"github.com/cilium/cilium/pkg/metrics"
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

	labelDir = "direction"

	labelDirIn  = "in"
	labelDirOut = "out"
	labelDirFwd = "fwd"
)

type xfrmCollector struct {
	xfrmErrorDesc    *prometheus.Desc
	nbKeysDesc       *prometheus.Desc
	nbXFRMStatesDesc *prometheus.Desc
	nbXFRMPolsDesc   *prometheus.Desc
}

func NewXFRMCollector() prometheus.Collector {
	return &xfrmCollector{
		xfrmErrorDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, subsystem, "xfrm_error"),
			"Total number of xfrm errors",
			[]string{labelErrorType, metrics.LabelError}, nil,
		),
		nbKeysDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, subsystem, "keys"),
			"Number of IPsec keys in use",
			[]string{}, nil,
		),
		nbXFRMStatesDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, subsystem, "xfrm_states"),
			"Number of XFRM states",
			[]string{labelDir}, nil,
		),
		nbXFRMPolsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, subsystem, "xfrm_policies"),
			"Number of XFRM policies",
			[]string{labelDir}, nil,
		),
	}
}

func (x *xfrmCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- x.xfrmErrorDesc
	ch <- x.nbKeysDesc
	ch <- x.nbXFRMStatesDesc
	ch <- x.nbXFRMPolsDesc
}

func (x *xfrmCollector) collectErrors(ch chan<- prometheus.Metric) {
	stats, err := procfs.NewXfrmStat()
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

func (x *xfrmCollector) collectConfigStats(ch chan<- prometheus.Metric) {
	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		log.WithError(err).Error("Failed to retrieve XFRM states to compute Prometheus metrics")
		return
	}
	nbKeys := ipsec.CountUniqueIPsecKeys(states)
	ch <- prometheus.MustNewConstMetric(x.nbKeysDesc, prometheus.GaugeValue, float64(nbKeys))

	nbStatesIn, nbStatesOut := ipsec.CountXfrmStatesByDir(states)
	ch <- prometheus.MustNewConstMetric(x.nbXFRMStatesDesc, prometheus.GaugeValue, float64(nbStatesIn), labelDirIn)
	ch <- prometheus.MustNewConstMetric(x.nbXFRMStatesDesc, prometheus.GaugeValue, float64(nbStatesOut), labelDirOut)

	policies, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		log.WithError(err).Error("Failed to retrieve XFRM policies to compute Prometheus metrics")
		return
	}
	nbPolIn, nbPolOut, nbPolFwd := ipsec.CountXfrmPoliciesByDir(policies)
	ch <- prometheus.MustNewConstMetric(x.nbXFRMPolsDesc, prometheus.GaugeValue, float64(nbPolIn), labelDirIn)
	ch <- prometheus.MustNewConstMetric(x.nbXFRMPolsDesc, prometheus.GaugeValue, float64(nbPolOut), labelDirOut)
	ch <- prometheus.MustNewConstMetric(x.nbXFRMPolsDesc, prometheus.GaugeValue, float64(nbPolFwd), labelDirFwd)
}

func (x *xfrmCollector) Collect(ch chan<- prometheus.Metric) {
	x.collectErrors(ch)
	x.collectConfigStats(ch)
}
