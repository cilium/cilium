// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/clustermesh/kvstoremesh"
)

var Cell = cell.Module(
	"kvstoremesh",
	"Cilium KVStoreMesh",

	cell.Config(kvstoremesh.DefaultConfig),
	cell.Invoke(registerClusterInfoValidator),

	APIServerCell,

	kvstoremesh.Cell,

	cell.Invoke(kvstoremesh.RegisterSyncWaiter),

	cell.Invoke(func(*kvstoremesh.KVStoreMesh) {}),
)
