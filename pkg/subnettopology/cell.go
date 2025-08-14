package subnettopology

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
)

type Params struct {
	cell.In

	Logger       *slog.Logger
	Registry     *metrics.Registry
	Lifecycle    cell.Lifecycle
	DaemonConfig *option.DaemonConfig

	JobGroup job.Group
}

var Cell = cell.Module(
	"subnet_topology",
	"Provides manager for subnet topology",
	cell.Invoke(registerDynamicManager),
)
