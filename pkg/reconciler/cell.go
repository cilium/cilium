package reconciler

import "github.com/cilium/cilium/pkg/hive/cell"

var Cell = cell.Module(
	"reconciler",
	"Generic reconciler",

	cell.Metric(newMetrics),
)
