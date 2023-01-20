// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"context"
	"fmt"
)

const dumpDirPerms = 0700

// Dir is a task that creates a directory, and schedules all of its subtasks
// to output in that directory.
type Dir struct {
	Base  `mapstructure:",squash"`
	Tasks []Task `mapstru`
}

func NewDir(name string, ts Tasks) *Dir {
	return &Dir{
		Base: Base{
			Kind: "Dir",
			Name: name,
		},
		Tasks: ts,
	}
}

// todo: make this immutable?
func (d *Dir) AddTasks(t ...Task) {
	d.Tasks = append(d.Tasks, t...)
}

func (d *Dir) Name() string {
	return d.Identifier()
}

func (d *Dir) Run(ctx context.Context, runtime Context) error {
	runtime = runtime.WithSubdir(d.Base.Name)
	if err := Initialize(runtime); err != nil {
		return fmt.Errorf("failed to initialize dir task %q: %w", d.Base.Name, err)
	}

	for _, task := range d.Tasks {
		if err := runtime.Submit(task.Identifier(), func(ctx context.Context) error {
			return task.Run(ctx, runtime)
		}); err != nil {
			return fmt.Errorf("failed to submit subtask: %w", err)
		}
	}
	return nil
}

func (d *Dir) Validate(ctx context.Context) error {
	if err := d.Base.validate(); err != nil {
		return fmt.Errorf("invalid dir %q: %w", d, err)
	}
	for _, t := range d.Tasks {
		if err := t.Validate(ctx); err != nil {
			return err
		}
	}
	return nil
}
