// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/metrics"
)

// initTestMetrics initializes NatGCSize and NatGCDeletedTotal metrics for
// testing, replacing the package-level NoOp vars with real Prometheus
// metrics so that gauge/counter values can be read back via testutil.
func initTestMetrics(t *testing.T) *metrics.LegacyMetrics {
	t.Helper()
	lm := metrics.NewLegacyMetrics()
	lm.NatGCSize.SetEnabled(true)
	lm.NatGCDeletedTotal.SetEnabled(true)
	metrics.NatGCSize = lm.NatGCSize
	metrics.NatGCDeletedTotal = lm.NatGCDeletedTotal
	t.Cleanup(func() {
		metrics.NatGCSize = metrics.NoOpGaugeVec
		metrics.NatGCDeletedTotal = metrics.NoOpCounterVec
	})
	return lm
}

func TestNatGCStatsFinish(t *testing.T) {
	t.Run("counter increment", func(t *testing.T) {
		lm := initTestMetrics(t)

		s := &NatGCStats{
			Family:         gcFamilyIPv4,
			IngressDeleted: 3,
			EgressDeleted:  5,
			IngressAlive:   10,
			EgressAlive:    8,
		}
		s.finish()

		assert.Equal(t, 3.0, testutil.ToFloat64(lm.NatGCDeletedTotal.WithLabelValues("ipv4", metricsIngress)))
		assert.Equal(t, 5.0, testutil.ToFloat64(lm.NatGCDeletedTotal.WithLabelValues("ipv4", metricsEgress)))
	})

	t.Run("gauge set", func(t *testing.T) {
		lm := initTestMetrics(t)

		s := &NatGCStats{
			Family:         gcFamilyIPv4,
			IngressDeleted: 3,
			EgressDeleted:  5,
			IngressAlive:   10,
			EgressAlive:    8,
		}
		s.finish()

		assert.Equal(t, 3.0, testutil.ToFloat64(lm.NatGCSize.WithLabelValues("ipv4", metricsIngress, metricsDeleted)))
		assert.Equal(t, 8.0, testutil.ToFloat64(lm.NatGCSize.WithLabelValues("ipv4", metricsEgress, metricsAlive)))
		assert.Equal(t, 10.0, testutil.ToFloat64(lm.NatGCSize.WithLabelValues("ipv4", metricsIngress, metricsAlive)))
		assert.Equal(t, 5.0, testutil.ToFloat64(lm.NatGCSize.WithLabelValues("ipv4", metricsEgress, metricsDeleted)))
	})

	t.Run("cumulative counter", func(t *testing.T) {
		lm := initTestMetrics(t)

		s := &NatGCStats{
			Family:         gcFamilyIPv4,
			IngressDeleted: 3,
			EgressDeleted:  5,
		}
		s.finish()
		s.finish()

		assert.Equal(t, 6.0, testutil.ToFloat64(lm.NatGCDeletedTotal.WithLabelValues("ipv4", metricsIngress)))
		assert.Equal(t, 10.0, testutil.ToFloat64(lm.NatGCDeletedTotal.WithLabelValues("ipv4", metricsEgress)))
	})

	t.Run("ipv6 family", func(t *testing.T) {
		lm := initTestMetrics(t)

		s := &NatGCStats{
			Family:         gcFamilyIPv6,
			IngressDeleted: 7,
			EgressDeleted:  2,
			IngressAlive:   1,
			EgressAlive:    4,
		}
		s.finish()

		assert.Equal(t, 7.0, testutil.ToFloat64(lm.NatGCDeletedTotal.WithLabelValues("ipv6", metricsIngress)))
		assert.Equal(t, 2.0, testutil.ToFloat64(lm.NatGCDeletedTotal.WithLabelValues("ipv6", metricsEgress)))
		assert.Equal(t, 7.0, testutil.ToFloat64(lm.NatGCSize.WithLabelValues("ipv6", metricsIngress, metricsDeleted)))
		assert.Equal(t, 4.0, testutil.ToFloat64(lm.NatGCSize.WithLabelValues("ipv6", metricsEgress, metricsAlive)))
	})
}
