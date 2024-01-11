package vitals

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/metrics"
	"github.com/cilium/cilium/pkg/vitals/health"
)

var Cell = cell.Module(
	"vitals",
	"Cilium Vitals Health",
	cell.Provide(func(healthMetrics *metrics.HealthMetrics, lc hive.Lifecycle) health.Health {
		fmt.Println("[tom-debug] creating vitals")
		hp := health.NewHealthProvider()
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
		return hp
	}),
	health.Cell,
)
