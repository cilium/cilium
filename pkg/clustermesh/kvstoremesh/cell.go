// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/kvstoremesh/reflector"
	"github.com/cilium/cilium/pkg/metrics"
)

var Cell = cell.Module(
	"kvstoremesh",
	"KVStoreMesh caches remote cluster information in a local kvstore",

	cell.Provide(
		common.DefaultRemoteClientFactory,
		newKVStoreMesh,
		newAPIClustersHandler,
	),

	cell.Config(common.DefaultConfig),

	// Don't pass ClusterMesh subsystem to prefer cilium_kvstoremesh_
	// instead of the more redundant cilium_kvstoremesh_clustermesh_
	metrics.Metric(common.MetricsProvider("")),
	metrics.Metric(MetricsProvider),

	reflector.Cell,
)
