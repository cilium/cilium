// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics_test

import (
	"context"
	"maps"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
)

type testMetrics struct {
	A metric.Gauge
	B metric.Counter
	C metric.Vec[metric.Observer]
}

func newTestMetrics() *testMetrics {
	return &testMetrics{
		A: metric.NewGauge(metric.GaugeOpts{
			Namespace: "test",
			Name:      "A",
			Disabled:  false,
		}),
		B: metric.NewCounter(metric.CounterOpts{
			Namespace: "test",
			Name:      "B",
			Disabled:  true,
		}),
		C: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: "test",
			Name:      "C_seconds",
		}, []string{"lbl"}),
	}
}

func TestMetricsCommand(t *testing.T) {
	log := hivetest.Logger(t)
	scripttest.Test(t,
		context.Background(),
		func(t testing.TB, args []string) *script.Engine {
			h := hive.New(
				metrics.Cell,
				metrics.Metric(newTestMetrics),
				cell.Provide(
					func() *option.DaemonConfig {
						return &option.DaemonConfig{}
					},
				),
				cell.Invoke(func(m *testMetrics) {
					m.A.Add(1)
					m.B.Add(2)
					o := m.C.WithLabelValues("a")
					o.Observe(0.01)
					o.Observe(0.01)
					o.Observe(0.1)
					o.Observe(1.0)
				}),
			)
			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.TODO()))
			})
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))
			return &script.Engine{
				Cmds: cmds,
			}
		}, []string{}, "testdata/*.txtar")
}
