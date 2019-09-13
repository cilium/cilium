// Copyright 2017 Authors of Cilium
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

package helpers

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/test/config"
	ginkgoext "github.com/cilium/cilium/test/ginkgo-ext"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

var (
	//SSHMetaLogs is a buffer where all commands sent over ssh are saved.
	SSHMetaLogs = ginkgoext.NewWriter(new(Buffer))
)

// SSHMeta contains metadata to SSH into a remote location to run tests
type SSHMeta struct {
	sshClient *SSHClient
	env       []string
	rawConfig []byte
	nodeName  string
	logger    *logrus.Entry
}

// CreateSSHMeta returns an SSHMeta with the specified host, port, and user, as
// well as an according SSHClient.
func CreateSSHMeta(host string, port int, user string) *SSHMeta {
	return &SSHMeta{
		sshClient: GetSSHClient(host, port, user),
	}
}

// Logger returns logger for SSHMeta
func (s *SSHMeta) Logger() *logrus.Entry {
	return s.logger
}

func (s *SSHMeta) String() string {
	return fmt.Sprintf("environment: %s, SSHClient: %s", s.env, s.sshClient.String())

}

// CloseSSHClient closes all of the connections made by the SSH Client for this
// SSHMeta.
func (s *SSHMeta) CloseSSHClient() {
	if s.sshClient == nil || s.sshClient.client == nil {
		log.Error("SSH client is nil; cannot close")
	}
	if err := s.sshClient.client.Close(); err != nil {
		log.WithError(err).Error("error closing SSH client")
	}
}

// GetVagrantSSHMeta returns a SSHMeta initialized based on the provided
// SSH-config target.
func GetVagrantSSHMeta(vmName string) *SSHMeta {
	config, err := GetVagrantSSHMetadata(vmName)
	if err != nil {
		return nil
	}

	log.Debugf("generated SSHConfig for node %s", vmName)
	nodes, err := ImportSSHconfig(config)
	if err != nil {
		log.WithError(err).Error("Error importing ssh config")
		return nil
	}
	var node *SSHConfig
	log.Debugf("done importing ssh config")
	for name := range nodes {
		if strings.HasPrefix(name, vmName) {
			node = nodes[name]
			break
		}
	}
	if node == nil {
		log.Errorf("Node %s not found in ssh config", vmName)
		return nil
	}
	sshMeta := &SSHMeta{
		sshClient: node.GetSSHClient(),
		rawConfig: config,
		nodeName:  vmName,
	}

	sshMeta.setBasePath()
	return sshMeta
}

// setBasePath if the SSHConfig is defined we set the BasePath to the GOPATH,
// from golang 1.8 GOPATH is by default $HOME/go so we also check that.
func (s *SSHMeta) setBasePath() {
	if config.CiliumTestConfig.SSHConfig == "" {
		return
	}

	gopath := s.Exec("echo $GOPATH").SingleOut()
	if gopath != "" {
		BasePath = filepath.Join(gopath, CiliumPath)
		return
	}

	home := s.Exec("echo $HOME").SingleOut()
	if home == "" {
		return
	}

	BasePath = filepath.Join(home, "go", CiliumPath)
	return
}

// ExecuteContext executes the given `cmd` and writes the cmd's stdout and
// stderr into the given io.Writers.
// Returns an error if context Deadline() is reached or if there was an error
// executing the command.
func (s *SSHMeta) ExecuteContext(ctx context.Context, cmd string, stdout io.Writer, stderr io.Writer) error {
	if stdout == nil {
		stdout = os.Stdout
	}

	if stderr == nil {
		stderr = os.Stderr
	}
	fmt.Fprintln(SSHMetaLogs, cmd)
	command := &SSHCommand{
		Path:   cmd,
		Stdin:  os.Stdin,
		Stdout: stdout,
		Stderr: stderr,
	}
	return s.sshClient.RunCommandContext(ctx, command)
}

// ExecWithSudo returns the result of executing the provided cmd via SSH using
// sudo.
func (s *SSHMeta) ExecWithSudo(cmd string, options ...ExecOptions) *CmdRes {
	command := fmt.Sprintf("sudo %s", cmd)
	return s.Exec(command, options...)
}

// ExecOptions options to execute Exec and ExecWithContext
type ExecOptions struct {
	SkipLog bool
}

// Exec returns the results of executing the provided cmd via SSH.
func (s *SSHMeta) Exec(cmd string, options ...ExecOptions) *CmdRes {
	// Bound all command executions to be at most the timeout used by the CI
	// so that commands do not block forever.
	ctx, cancel := context.WithTimeout(context.Background(), HelperTimeout)
	defer cancel()
	return s.ExecContext(ctx, cmd, options...)
}

// ExecShort runs command with the provided options. It will take up to
// ShortCommandTimeout seconds to run the command before it times out.
func (s *SSHMeta) ExecShort(cmd string, options ...ExecOptions) *CmdRes {
	ctx, cancel := context.WithTimeout(context.Background(), ShortCommandTimeout)
	defer cancel()
	return s.ExecContext(ctx, cmd, options...)
}

// ExecMiddle runs command with the provided options. It will take up to
// MidCommandTimeout seconds to run the command before it times out.
func (s *SSHMeta) ExecMiddle(cmd string, options ...ExecOptions) *CmdRes {
	ctx, cancel := context.WithTimeout(context.Background(), MidCommandTimeout)
	defer cancel()
	return s.ExecContext(ctx, cmd, options...)
}

// ExecContextShort is a wrapper around ExecContext which creates a child
// context with a timeout of ShortCommandTimeout.
func (s *SSHMeta) ExecContextShort(ctx context.Context, cmd string, options ...ExecOptions) *CmdRes {
	shortCtx, cancel := context.WithTimeout(ctx, ShortCommandTimeout)
	defer cancel()
	return s.ExecContext(shortCtx, cmd, options...)
}

// ExecContext returns the results of executing the provided cmd via SSH.
func (s *SSHMeta) ExecContext(ctx context.Context, cmd string, options ...ExecOptions) *CmdRes {
	var ops ExecOptions
	if len(options) > 0 {
		ops = options[0]
	}

	log.Debugf("running command: %s", cmd)
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
		res.success = false
		// Set error code to 1 in case that it's another error to see that the
		// command failed. If the default value (0) indicates that command
		// works but it was not executed at all.
		res.exitcode = 1
		exiterr, isExitError := err.(*ssh.ExitError)
		if isExitError {
			// Set res's exitcode if the error is an ExitError
			res.exitcode = exiterr.Waitmsg.ExitStatus()
		} else {
			// Log other error types. They are likely from SSH or the network
			log.WithError(err).Errorf("Error executing command '%s'", cmd)
			res.err = err
		}
	}

	res.SendToLog(ops.SkipLog)
	return &res
}

// GetCopy returns a copy of SSHMeta, useful for parallel requests
func (s *SSHMeta) GetCopy() *SSHMeta {
	nodes, err := ImportSSHconfig(s.rawConfig)
	if err != nil {
		log.WithError(err).Error("while importing ssh config for meta copy")
		return nil
	}

	config := nodes[s.nodeName]
	if config == nil {
		log.Errorf("no node %s in imported config", s.nodeName)
		return nil
	}

	copy := &SSHMeta{
		sshClient: config.GetSSHClient(),
		rawConfig: s.rawConfig,
		nodeName:  s.nodeName,
	}

	return copy
}

// ExecInBackground returns the results of running cmd via SSH in the specified
// context. The command will be executed in the background until context.Context
// is canceled or the command has finish its execution.
func (s *SSHMeta) ExecInBackground(ctx context.Context, cmd string, options ...ExecOptions) *CmdRes {
	if ctx == nil {
		panic("no context provided")
	}

	var ops ExecOptions
	if len(options) > 0 {
		ops = options[0]
	}

	fmt.Fprintln(SSHMetaLogs, cmd)
	stdout := new(Buffer)
	stderr := new(Buffer)

	command := &SSHCommand{
		Path:   cmd,
		Stdin:  os.Stdin,
		Stdout: stdout,
		Stderr: stderr,
	}
	var wg sync.WaitGroup
	res := &CmdRes{
		cmd:     cmd,
		stdout:  stdout,
		stderr:  stderr,
		success: false,
		wg:      &wg,
	}

	res.wg.Add(1)
	go func(res *CmdRes) {
		defer res.wg.Done()
		start := time.Now()
		err := s.sshClient.RunCommandInBackground(ctx, command)
		if err != nil {
			exiterr, isExitError := err.(*ssh.ExitError)
			if isExitError {
				res.exitcode = exiterr.Waitmsg.ExitStatus()
				// Set success as true if SIGINT signal was sent to command
				if res.exitcode == 130 {
					res.success = true
				}
			}
		} else {
			res.success = true
			res.exitcode = 0
		}
		res.duration = time.Since(start)
		res.SendToLog(ops.SkipLog)
	}(res)

	return res
}
