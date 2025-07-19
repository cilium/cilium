// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package workqueuemetrics

import (
	"github.com/cilium/hive/cell"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/metrics"
)

var Cell = cell.Module(
	"workqueue-metrics-provider",
	"Metrics provider for client-go workqueues",

	metrics.Metric(NewMetrics),
	cell.Provide(func(m *Metrics) workqueue.MetricsProvider { return m }),
)
