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
	"Registry of datapath MapSpecs that can be modified during Hive construction",
	cell.Provide(provide),
)

// provide provides a MapRegistry to the Hive.
func provide(lc cell.Lifecycle, log *slog.Logger, jg job.Group) (*MapRegistry, error) {
	reg, err := new(log)
	if err != nil {
		return nil, err
	}

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			return reg.start()
		},
	})

	jg.Add(
		job.OneShot("registry", func(ctx context.Context, health cell.Health) error {
			health.OK("Registry started and read-only")
			return nil
		}))

	return reg, nil
}
