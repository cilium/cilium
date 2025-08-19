package subnettopology

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive/cell"
)

type Params struct {
	cell.In

	Logger       *slog.Logger
	Registry     *metrics.Registry
	Lifecycle    cell.Lifecycle
	DaemonConfig *option.DaemonConfig

	M *Map
}

var Cell = cell.Module(
	"subnet_topology",
	"Provides manager for subnet topology",
	cell.ProvidePrivate(
		func(reg *metrics.Registry) *Map {
			return SubnetMap(reg)
		},
	),
	cell.Invoke(registerDynamicManager),
)
