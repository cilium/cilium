// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"context"
	"fmt"

	"go.uber.org/multierr"
)

const dumpDirPerms = 0700

// Dir is a task that creates a directory, and schedules all of its subtasks
// to output in that directory.
type Dir struct {
	base  `mapstructure:",squash"`
	Tasks []Task `mapstructure:"tasks"`
}

func NewDir(name string, ts Tasks) *Dir {
	return &Dir{
		base: base{
			Kind: "Dir",
			Name: name,
		},
		Tasks: ts,
	}
}

func (d *Dir) Name() string {
	return d.Identifier()
}

func (d *Dir) Run(ctx context.Context, runtime Context) error {
	runtime = runtime.WithSubdir(d.base.Name)
	if err := Initialize(runtime); err != nil {
		return fmt.Errorf("failed to initialize dir task %q: %w", d.base.Name, err)
	}

	for _, task := range d.Tasks {
		if err := task.Run(ctx, runtime); err != nil {
			return err
		}
	}
	return nil
}

func (d *Dir) Validate(ctx context.Context) error {
	var acc error
	for _, t := range d.Tasks {
		if err := t.Validate(ctx); err != nil {
			acc = multierr.Append(acc, err)
		}
	}
	if err := d.base.validate(); err != nil {
		acc = multierr.Append(acc, fmt.Errorf("invalid dir %q: %w", d, err))
	}
	return acc
}
