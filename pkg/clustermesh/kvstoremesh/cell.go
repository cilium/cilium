// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/metrics"
)

var Cell = cell.Module(
	"kvstoremesh",
	"KVStoreMesh caches remote cluster information in a local kvstore",

	cell.Provide(
		newKVStoreMesh,
		newAPIClustersHandler,
	),

	cell.Config(common.DefaultConfig),

	metrics.Metric(common.MetricsProvider("")),
)
