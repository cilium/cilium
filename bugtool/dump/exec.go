// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"time"

	"github.com/cilium/cilium/bugtool/cmd"
	log "github.com/sirupsen/logrus"
)

// Exec gathers data resource from the stdout/stderr of
// execing a command.
type Exec struct {
	base `mapstructure:",squash"`
	Ext  string

	Cmd                string
	HashEncryptionKeys bool
	Args               []string
}

func (e *Exec) Validate(ctx context.Context) error {
	log.Debugf("validating: %s", e.Identifier())
	if err := e.base.validate(); err != nil {
		return fmt.Errorf("invalid exec %q: %w", e.GetName(), err)
	}
	return nil
}

func NewExec(name string, ext string, cmd string, args ...string) *Exec {
	return &Exec{
		base: base{
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

		var buf *bytes.Buffer
		if e.HashEncryptionKeys {
			buf = bytes.NewBuffer([]byte{})
			c.Stdout = buf
		} else {
			c.Stdout = fd
		}
		c.Stderr = errFd

		startTime := time.Now()
		var runErr error
		if runErr = c.Run(); runErr != nil {
			return runErr
		}

		if e.HashEncryptionKeys {
			fd.Write(cmd.HashEncryptionKeys(buf.Bytes()))
		}

		usage := c.ProcessState.SysUsage()
		defer func() {
			var ru *syscall.Rusage
			if rusage, ok := usage.(*syscall.Rusage); ok {
				ru = rusage
			}
			runtime.AddResult(TaskResult{
				Name:           e.Identifier(),
				StartTime:      startTime,
				Duration:       time.Since(startTime).String(),
				OutputFilePath: e.Filename(),

				Usage: ru,
				Error: runErr,
				Code:  c.ProcessState.ExitCode(),
			})
		}()

		return nil
	})
}
