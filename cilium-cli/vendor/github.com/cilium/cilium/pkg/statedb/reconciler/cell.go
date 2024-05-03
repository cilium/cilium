// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/metrics"
)

// Cell provides shared objects used by all reconciler instances.
// Currently it provides only the Metrics object.
var Cell = cell.Module(
	"reconciler",
	"Shared metrics for the reconcilers",

	metrics.Metric(newMetrics),
)
