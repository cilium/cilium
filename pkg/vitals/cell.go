package vitals

import (
	"context"

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
		hp.Start(context.Background())
		lc.Append(hive.Hook{
			OnStop: func(ctx hive.HookContext) error {
				hp.Stop(ctx)
				return nil
			},
		})
	}),
	health.Cell,
)
