// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	ginkgoext "github.com/cilium/cilium/test/ginkgo-ext"
)

var (
	//LocalExecutorLogs is a buffer where all commands sent over ssh are saved.
	LocalExecutorLogs = ginkgoext.NewWriter(new(Buffer))
)

// Executor executes commands
type Executor interface {
	IsLocal() bool
	CloseSSHClient()
	Exec(cmd string, options ...ExecOptions) *CmdRes
	ExecContext(ctx context.Context, cmd string, options ...ExecOptions) *CmdRes
	ExecContextShort(ctx context.Context, cmd string, options ...ExecOptions) *CmdRes
	ExecInBackground(ctx context.Context, cmd string, options ...ExecOptions) *CmdRes
	ExecMiddle(cmd string, options ...ExecOptions) *CmdRes
	ExecShort(cmd string, options ...ExecOptions) *CmdRes
	ExecWithSudo(cmd string, options ...ExecOptions) *CmdRes
	ExecuteContext(ctx context.Context, cmd string, stdout io.Writer, stderr io.Writer) error
	String() string
	BasePath() string
	RenderTemplateToFile(filename string, tmplt string, perm os.FileMode) error
	setBasePath()

	Logger() *logrus.Entry
}

// LocalExecutor executes commands, implements Executor interface
type LocalExecutor struct {
	env      []string
	logger   *logrus.Entry
	basePath string
}

// CreateLocalExecutor returns a local executor
func CreateLocalExecutor(env []string) *LocalExecutor {
	return &LocalExecutor{env: env}
}

// IsLocal returns true if commands are executed on the Ginkgo host
func (s *LocalExecutor) IsLocal() bool {
	return true
}

// Logger returns logger for executor
func (s *LocalExecutor) Logger() *logrus.Entry {
	return s.logger
}

func (s *LocalExecutor) String() string {
	return fmt.Sprintf("environment: %s", s.env)

}

// CloseSSHClient is a no-op
func (s *LocalExecutor) CloseSSHClient() {
}

func (s *LocalExecutor) setBasePath() {
	wd, err := os.Getwd()
	if err != nil {
		ginkgoext.Fail(fmt.Sprintf("Cannot set base path: %s", err.Error()), 1)
		return
	}
	s.basePath = wd

}

func (s LocalExecutor) getLocalCmd(ctx context.Context, command string, stdout io.Writer, stderr io.Writer) *exec.Cmd {
	com := "bash"
	args := []string{"-c", command}

	cmd := exec.CommandContext(ctx, com, args...)
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}

	fmt.Fprintln(LocalExecutorLogs, cmd)
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	cmd.Env = s.env

	return cmd
}

// ExecuteContext executes the given `cmd` and writes the cmd's stdout and
// stderr into the given io.Writers.
// Returns an error if context Deadline() is reached or if there was an error
// executing the command.
func (s *LocalExecutor) ExecuteContext(ctx context.Context, command string, stdout io.Writer, stderr io.Writer) error {
	cmd := s.getLocalCmd(ctx, command, stdout, stderr)
	return cmd.Run()
}

// ExecWithSudo returns the result of executing the provided cmd via SSH using
// sudo.
func (s *LocalExecutor) ExecWithSudo(cmd string, options ...ExecOptions) *CmdRes {
	command := fmt.Sprintf("sudo %s", cmd)
	return s.Exec(command, options...)
}

// Exec returns the results of executing the provided cmd via SSH.
func (s *LocalExecutor) Exec(cmd string, options ...ExecOptions) *CmdRes {
	// Bound all command executions to be at most the timeout used by the CI
	// so that commands do not block forever.
	ctx, cancel := context.WithTimeout(context.Background(), HelperTimeout)
	defer cancel()
	return s.ExecContext(ctx, cmd, options...)
}

// ExecShort runs command with the provided options. It will take up to
// ShortCommandTimeout seconds to run the command before it times out.
func (s *LocalExecutor) ExecShort(cmd string, options ...ExecOptions) *CmdRes {
	ctx, cancel := context.WithTimeout(context.Background(), ShortCommandTimeout)
	defer cancel()
	return s.ExecContext(ctx, cmd, options...)
}

// ExecMiddle runs command with the provided options. It will take up to
// MidCommandTimeout seconds to run the command before it times out.
func (s *LocalExecutor) ExecMiddle(cmd string, options ...ExecOptions) *CmdRes {
	ctx, cancel := context.WithTimeout(context.Background(), MidCommandTimeout)
	defer cancel()
	return s.ExecContext(ctx, cmd, options...)
}

// ExecContextShort is a wrapper around ExecContext which creates a child
// context with a timeout of ShortCommandTimeout.
func (s *LocalExecutor) ExecContextShort(ctx context.Context, cmd string, options ...ExecOptions) *CmdRes {
	shortCtx, cancel := context.WithTimeout(ctx, ShortCommandTimeout)
	defer cancel()
	return s.ExecContext(shortCtx, cmd, options...)
}

// ExecContext returns the results of executing the provided cmd via SSH.
func (s *LocalExecutor) ExecContext(ctx context.Context, cmd string, options ...ExecOptions) *CmdRes {
	var ops ExecOptions
	if len(options) > 0 {
		ops = options[0]
	}

	log.Debugf("running local command: %s", cmd)
	fmt.Fprintln(SSHMetaLogs, cmd)
	stdout := new(Buffer)
	stderr := new(Buffer)
	start := time.Now()
	err := s.ExecuteContext(ctx, cmd, stdout, stderr)

	res := CmdRes{
		cmd:      cmd,
		stdout:   stdout,
		stderr:   stderr,
		success:  true, // this may be toggled when err != nil below
		duration: time.Since(start),
	}

	if err != nil {

		if exitError, ok := err.(*exec.ExitError); ok {
			res.exitcode = exitError.ExitCode()
		}
		res.success = false

		log.WithError(err).Errorf("Error executing local command '%s'", cmd)
		res.err = err
	}

	res.SendToLog(ops.SkipLog)
	return &res
}

// ExecInBackground returns the results of running cmd in the specified
// context. The command will be executed in the background until context.Context
// is canceled or the command has finish its execution.
func (s *LocalExecutor) ExecInBackground(ctx context.Context, cmd string, options ...ExecOptions) *CmdRes {
	if ctx == nil {
		panic("no context provided")
	}

	var ops ExecOptions
	if len(options) > 0 {
		ops = options[0]
	}

	fmt.Fprintln(LocalExecutorLogs, cmd)
	stdout := new(Buffer)
	stderr := new(Buffer)

	command := s.getLocalCmd(ctx, cmd, stdout, stderr)

	var wg sync.WaitGroup
	res := &CmdRes{
		cmd:     cmd,
		stdout:  stdout,
		stderr:  stderr,
		success: true,
		wg:      &wg,
	}

	res.wg.Add(1)
	go func(cmd *exec.Cmd, res *CmdRes) {
		defer res.wg.Done()
		start := time.Now()
		err := cmd.Run()
		res.duration = time.Since(start)

		if err != nil {
			if exitError, ok := err.(*exec.ExitError); ok {
				res.exitcode = exitError.ExitCode()
			}
			res.success = false

			log.WithError(err).Errorf("Error executing local background command '%s'", strings.Join(append([]string{cmd.Path}, cmd.Args...), " "))
			res.err = err
		}

		res.SendToLog(ops.SkipLog)
	}(command, res)

	return res
}

func (s *LocalExecutor) BasePath() string {
	return s.basePath
}

// RenderTemplateToFile renders a text/template string into a target filename
// with specific persmisions. Returns an error if the template cannot be
// validated or the file cannot be created.
func (s *LocalExecutor) RenderTemplateToFile(filename string, tmplt string, perm os.FileMode) error {
	content, err := RenderTemplate(tmplt)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, content.Bytes(), perm)
}
