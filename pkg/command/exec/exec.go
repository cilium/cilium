// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package exec

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/sirupsen/logrus"
)

// CombinedOutput runs the command 'cmd' which was initialized with reference
// to 'ctx', and logs an error to 'scopedLog', with more verbosity if 'verbose'
// is set to true.
//
// Returns any error (including timeout) that may have occurred during
// execution of 'cmd'.
func CombinedOutput(ctx context.Context, cmd *exec.Cmd, scopedLog *logrus.Entry, verbose bool) ([]byte, error) {
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		scopedLog.WithField("cmd", cmd.Args).Error("Command execution failed: Timeout")
		return nil, fmt.Errorf("Command execution failed: Timeout for %s", cmd.Args)
	}
	if err != nil {
		if verbose {
			scopedLog.WithError(err).WithField("cmd", cmd.Args).Error("Command execution failed")

			scanner := bufio.NewScanner(bytes.NewReader(out))
			for scanner.Scan() {
				scopedLog.Warn(scanner.Text())
			}
		}
	}
	return out, err
}

// Cmd wraps exec.Cmd with a context to provide convenient execution of a
// command with nice checking of the context timeout in the form:
//
// err := exec.Prog().WithTimeout(5*time.Second, myprog, myargs...).CombinedOutput(log, verbose)
type Cmd struct {
	*exec.Cmd
	ctx      context.Context
	cancelFn func()
}

// CommandContext wraps exec.CommandContext to allow this package to be used as
// a drop-in replacement for the standard exec library.
func CommandContext(ctx context.Context, prog string, args ...string) *Cmd {
	return &Cmd{
		Cmd: exec.CommandContext(ctx, prog, args...),
		ctx: ctx,
	}
}

// WithTimeout creates a Cmd with a context that times out after the specified
// duration.
func WithTimeout(timeout time.Duration, prog string, args ...string) *Cmd {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	cmd := CommandContext(ctx, prog, args...)
	cmd.cancelFn = cancel
	return cmd
}

// CombinedOutput runs the command and returns its combined standard output and
// standard error. Unlike the standard library, if the context is exceeded, it
// will return an error indicating so.
//
// Logs any errors that occur to the specified logger.
func (c *Cmd) CombinedOutput(scopedLog *logrus.Entry, verbose bool) ([]byte, error) {
	out, err := CombinedOutput(c.ctx, c.Cmd, scopedLog, verbose)
	if c.cancelFn != nil {
		c.cancelFn()
	}
	return out, err
}
