package vitals

import (
	"strings"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/metrics"
	"github.com/cilium/cilium/pkg/vitals/health"
)

var Cell = cell.Module(
	"vitals",
	"Cilium Vitals Health",
	cell.Provide(health.NewHealthProvider),
	cell.Invoke(func(healthMetrics *metrics.HealthMetrics, lc hive.Lifecycle, hp health.Health) {
		updateStats := func() {
			for l, c := range hp.Stats() {
				healthMetrics.HealthStatusGauge.WithLabelValues(strings.ToLower(string(l))).Set(float64(c))
			}
		}
		lc.Append(hive.Hook{
			OnStart: func(ctx hive.HookContext) error {
				updateStats()
				hp.Subscribe(ctx, func(u health.Update) {
					updateStats()
				}, func(err error) {})
				return nil
			},
			OnStop: func(ctx hive.HookContext) error {
				return hp.Stop(ctx)
			},
		})
	}),
	health.Cell,
)
