// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/time"
)

type bootstrapStatistics struct {
	overall   spanstat.SpanStat
	earlyInit spanstat.SpanStat
	k8sInit   spanstat.SpanStat
	ipam      spanstat.SpanStat
	kvstore   spanstat.SpanStat
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
		"overall":   &b.overall,
		"earlyInit": &b.earlyInit,
		"k8sInit":   &b.k8sInit,
		"ipam":      &b.ipam,
		"kvstore":   &b.kvstore,
	}
}
