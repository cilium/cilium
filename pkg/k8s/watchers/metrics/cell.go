// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"github.com/cilium/hive/cell"
	"k8s.io/client-go/util/workqueue"
)

var Cell = cell.Module(
	"k8s-workqueue-metrics",
	"K8s workqueue metrics provider",
	cell.Provide(func() workqueue.MetricsProvider {
		return &workqueueMetricsProvider{}
	}),
)
