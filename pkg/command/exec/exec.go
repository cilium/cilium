// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

package exec

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

func warnToLog(cmd *exec.Cmd, filters []string, out []byte, scopedLog *logrus.Entry, err error) {
	scopedLog.WithError(err).WithField("cmd", cmd.Args).Error("Command execution failed")
	scanner := bufio.NewScanner(bytes.NewReader(out))
scan:
	for scanner.Scan() {
		text := scanner.Text()
		for _, filter := range filters {
			if strings.Contains(text, filter) {
				continue scan
			}
		}
		scopedLog.Warn(text)
	}
}

// combinedOutput is the core implementation of catching deadline exceeded
// options and logging errors, with an optional set of filtered outputs.
func combinedOutput(ctx context.Context, cmd *exec.Cmd, filters []string, scopedLog *logrus.Entry, verbose bool) ([]byte, error) {
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		scopedLog.WithError(err).WithField("cmd", cmd.Args).Error("Command execution failed")
		return nil, fmt.Errorf("Command execution failed for %s: %s", cmd.Args, ctx.Err())
	}
	if err != nil && verbose {
		warnToLog(cmd, filters, out, scopedLog, err)
	}
	return out, err
}

// output is the equivalent to combinedOutput with only capturing stdout
func output(ctx context.Context, cmd *exec.Cmd, filters []string, scopedLog *logrus.Entry, verbose bool) ([]byte, error) {
	out, err := cmd.Output()
	if ctx.Err() != nil {
		scopedLog.WithError(err).WithField("cmd", cmd.Args).Error("Command execution failed")
		return nil, fmt.Errorf("Command execution failed for %s: %s", cmd.Args, ctx.Err())
	}
	if err != nil && verbose {
		warnToLog(cmd, filters, out, scopedLog, err)
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

	// filters is a slice of strings that should be omitted from logging.
	filters []string
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

// WithCancel creates a Cmd with a context that can be cancelled by calling the
// resulting Cancel() function.
func WithCancel(ctx context.Context, prog string, args ...string) (*Cmd, context.CancelFunc) {
	newCtx, cancel := context.WithCancel(ctx)
	cmd := CommandContext(newCtx, prog, args...)
	return cmd, cancel
}

// WithFilters modifies the specified command to filter any output lines from
// logs if they contain any of the substrings specified as arguments to this
// function.
func (c *Cmd) WithFilters(filters ...string) *Cmd {
	c.filters = append(c.filters, filters...)
	return c
}

// CombinedOutput runs the command and returns its combined standard output and
// standard error. Unlike the standard library, if the context is exceeded, it
// will return an error indicating so.
//
// Logs any errors that occur to the specified logger.
func (c *Cmd) CombinedOutput(scopedLog *logrus.Entry, verbose bool) ([]byte, error) {
	out, err := combinedOutput(c.ctx, c.Cmd, c.filters, scopedLog, verbose)
	if c.cancelFn != nil {
		c.cancelFn()
	}
	return out, err
}

// Output runs the command and returns only standard output, but not the
// standard error. Unlike the standard library, if the context is exceeded,
// it will return an error indicating so.
//
// Logs any errors that occur to the specified logger.
func (c *Cmd) Output(scopedLog *logrus.Entry, verbose bool) ([]byte, error) {
	out, err := output(c.ctx, c.Cmd, c.filters, scopedLog, verbose)
	if c.cancelFn != nil {
		c.cancelFn()
	}
	return out, err
}
