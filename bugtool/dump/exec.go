// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/cilium/bugtool/utils"

	log "github.com/sirupsen/logrus"
)

// Exec gathers data resource from the stdout/stderr of
// execing a command.
type Exec struct {
	base `mapstructure:",squash"`
	Ext  string

	Cmd                string `json:"cmd"`
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

func (e *Exec) filename() string {
	return fmt.Sprintf("%s.%s", e.GetName(), e.Ext)
}

func (e *Exec) Run(ctx context.Context, runtime Context) error {
	return runtime.Submit(ctx, e.Identifier(), func(ctx context.Context) error {
		fd, err := runtime.CreateTaskFile(e.filename())
		if err != nil {
			return fmt.Errorf("failed to create file for %q: %w", e.Identifier(), err)
		}
		defer fd.Close()
		errFd, err := runtime.CreateTaskFile(e.filename() + ".err")
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
		defer func() {
			tr := TaskResult{
				Name:           e.Identifier(),
				Command:        strings.Join(c.Args, " "),
				StartTime:      startTime,
				Duration:       time.Since(startTime).String(),
				OutputFilePath: e.filename(),

				Error: runErr,
				Code:  c.ProcessState.ExitCode(),
			}
			if c.ProcessState != nil {
				if rusage, ok := c.ProcessState.SysUsage().(*syscall.Rusage); ok && rusage != nil {
					tr.MaxResidentSetSize = rusage.Maxrss
					tr.KernelTime = rusage.Stime.Nano()
					tr.UserTime = rusage.Utime.Nano()
				}
			}
			runtime.AddResult(tr)
		}()
		if runErr = c.Run(); runErr != nil {
			return runErr
		}

		if e.HashEncryptionKeys {
			fd.Write(utils.HashEncryptionKeys(buf.Bytes()))
		}

		return nil
	})
}
