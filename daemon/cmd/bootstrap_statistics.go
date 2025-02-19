// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/time"
)

type bootstrapStatistics struct {
	overall         spanstat.SpanStat
	earlyInit       spanstat.SpanStat
	k8sInit         spanstat.SpanStat
	restore         spanstat.SpanStat
	healthCheck     spanstat.SpanStat
	ingressIPAM     spanstat.SpanStat
	cleanup         spanstat.SpanStat
	bpfBase         spanstat.SpanStat
	ipam            spanstat.SpanStat
	daemonInit      spanstat.SpanStat
	mapsInit        spanstat.SpanStat
	fqdn            spanstat.SpanStat
	enableConntrack spanstat.SpanStat
	kvstore         spanstat.SpanStat
	deleteQueue     spanstat.SpanStat
}

func (b *bootstrapStatistics) updateMetrics() {
	if !metrics.BootstrapTimes.IsEnabled() {
		return
	}

	for scope, stat := range b.getMap() {
		if stat.SuccessTotal() != time.Duration(0) {
			metrics.BootstrapTimes.WithLabelValues(scope, metrics.LabelValueOutcomeSuccess).Set(stat.SuccessTotal().Seconds())
		}
		if stat.FailureTotal() != time.Duration(0) {
			metrics.BootstrapTimes.WithLabelValues(scope, metrics.LabelValueOutcomeFail).Set(stat.FailureTotal().Seconds())
		}
	}
}

func (b *bootstrapStatistics) getMap() map[string]*spanstat.SpanStat {
	return map[string]*spanstat.SpanStat{
		"overall":         &b.overall,
		"earlyInit":       &b.earlyInit,
		"k8sInit":         &b.k8sInit,
		"restore":         &b.restore,
		"healthCheck":     &b.healthCheck,
		"ingressIPAM":     &b.ingressIPAM,
		"cleanup":         &b.cleanup,
		"bpfBase":         &b.bpfBase,
		"ipam":            &b.ipam,
		"daemonInit":      &b.daemonInit,
		"mapsInit":        &b.mapsInit,
		"fqdn":            &b.fqdn,
		"enableConntrack": &b.enableConntrack,
		"kvstore":         &b.kvstore,
		"deleteQueue":     &b.deleteQueue,
	}
}
