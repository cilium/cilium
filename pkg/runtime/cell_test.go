// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package runtime

import (
	"context"
	"runtime/metrics"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/inctimer"
	cmx "github.com/cilium/cilium/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

func TestOnStart(t *testing.T) {
	var (
		logger, _ = test.NewNullLogger()
		cfg       = Config{RuntimeCheckInterval: 100 * time.Millisecond}
	)

	uu := map[string]struct {
		hits      int
		collected float64
		metrics   RuntimeMetrics
	}{
		"none": {
			hits:      1,
			collected: 0,
			metrics:   newTestRTMetrics(nil),
		},

		"empty": {
			hits:      1,
			collected: 0,
			metrics: newTestRTMetrics(&metrics.Float64Histogram{
				Counts:  []uint64{},
				Buckets: []float64{},
			}),
		},

		"sparse": {
			hits:      1,
			collected: 10,
			metrics: newTestRTMetrics(&metrics.Float64Histogram{
				Counts:  []uint64{50, 0},
				Buckets: []float64{10},
			}),
		},

		"full": {
			hits:      1,
			collected: 20,
			metrics: newTestRTMetrics(&metrics.Float64Histogram{
				Counts:  []uint64{50, 100, 10, 60},
				Buckets: []float64{10, 20, 30, 40},
			}),
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			cmx.RuntimeSchedulerLatency = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: cmx.Namespace,
				Name:      cmx.RuntimeSchedLatencyMX,
			}, []string{"kind"})

			var (
				ctx, cancel = context.WithCancel(context.Background())
				hctx        = hive.HookContext(context.Background())
			)
			f := _start(ctx, logger, cfg, u.metrics)
			assert.NoError(t, f(hctx))

			<-inctimer.After(2 * time.Millisecond)
			sf := _stop(cancel, logger)
			sf(hctx)

			assert.Equal(t, u.hits, u.hits)
			assert.Equal(t, u.collected, getMetricValue(cmx.RuntimeSchedulerLatency))
		})
	}
}
