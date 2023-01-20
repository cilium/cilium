// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"syscall"
)

// Exec gathers data resource from the stdout/stderr of
// execing a command.
type Exec struct {
	Base `mapstructure:",squash"`
	Ext  string

	Cmd  string
	Args []string

	clauses []Clause
	filter  func(io.Reader, io.Writer) error
}

func (e *Exec) Validate(ctx context.Context) error {
	if err := e.Base.validate(); err != nil {
		return fmt.Errorf("invalid exec %q: %w", e.GetName(), err)
	}
	return nil
}

func NewCommand(name string, ext string, cmd string, args ...string) *Exec {
	return &Exec{
		Base: Base{
			Name: name,
			Kind: "Exec",
		},
		Cmd:  cmd,
		Args: args,
		Ext:  ext,
	}
}

func (f *Exec) Filename() string {
	return fmt.Sprintf("%s.%s", f.GetName(), f.Ext)
}

func (e *Exec) Run(ctx context.Context, runtime Context) error {
	return runtime.Submit(e.Identifier(), func(ctx context.Context) error {
		fd, err := runtime.CreateFile(e.Filename())
		if err != nil {
			return fmt.Errorf("failed to create file for %q: %w", e.Identifier(), err)
		}
		defer fd.Close()
		errFd, err := runtime.CreateErrFile(e.Filename() + ".err")
		if err != nil {
			return fmt.Errorf("failed to create file for %q: %w", e.Identifier(), err)
		}
		defer errFd.Close()

		c := exec.CommandContext(ctx, e.Cmd, e.Args...)
		c.Stdout = fd
		c.Stderr = errFd

		if err := c.Run(); err != nil {
			return err
		}
		usage := c.ProcessState.SysUsage()
		defer func() {
			if rusage, ok := usage.(*syscall.Rusage); ok {
				runtime.AddResult(TaskResult{
					Name:  e.Identifier(),
					Usage: rusage,
				})
			}
		}()

		return ctx.Err()
	})
}
