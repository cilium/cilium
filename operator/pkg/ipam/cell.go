// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/ipam/allocator"
)

var allocators []cell.Cell

func Cell() cell.Cell {
	return cell.Module(
		"ip-allocator-provider",
		"Operator IP allocator provider",

		cell.Config(defaultConfig),
		cell.ProvidePrivate(newNodeWatcherJobFactory),

		cell.Group(allocators...),
	)
}

type Config struct {
	ParallelAllocWorkers int64
}

var defaultConfig = Config{
	ParallelAllocWorkers: 50,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Int64(option.ParallelAllocWorkers, defaultConfig.ParallelAllocWorkers, "Maximum number of parallel IPAM workers")
}

type nodeWatcherJobFactory func(nm allocator.NodeEventHandler) job.Job
