// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/ipam/allocator"
)

var Cell = cell.Module(
	"ip-allocator-provider",
	"Operator IP allocator provider",

	cell.ProvidePrivate(newNodeWatcherJobFactory),

	cell.Group(
		clusterPoolCell,
	),
)

type nodeWatcherJobFactory func(nm allocator.NodeEventHandler) job.Job
