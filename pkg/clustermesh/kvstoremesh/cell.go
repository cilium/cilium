// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"github.com/cilium/cilium/pkg/clustermesh/internal"
	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"kvstoremesh",
	"KVStoreMesh caches remote cluster information in a local kvstore",

	cell.Provide(newKVStoreMesh),

	cell.Config(internal.Config{}),

	cell.Metric(internal.MetricsProvider("")),
)
