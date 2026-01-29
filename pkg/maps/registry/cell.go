// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package registry

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
)

var Cell = cell.Module(
	"registry",
	"Registry of eBPF map specifications that can be modified",
	cell.Provide(new),
)

type registryParams struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	JobGroup  job.Group
}

func new(p registryParams) (*MapRegistry, error) {
	reg, err := newMapRegistry(p)
	if err != nil {
		return nil, err
	}

	p.Lifecycle.Append(reg)

	p.JobGroup.Add(
		job.OneShot("registry", func(ctx context.Context, health cell.Health) error {
			health.OK("Registry started and read-only")
			return nil
		}))

	return reg, nil
}
