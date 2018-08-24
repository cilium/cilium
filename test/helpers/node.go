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

func (s *SSHMeta) String() string {
	return fmt.Sprintf("environment: %s, SSHClient: %s", s.env, s.sshClient.String())

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

// Execute executes cmd on the provided node and stores the stdout / stderr of
// the command in the provided buffers. Returns false if the command failed
// during its execution.
func (s *SSHMeta) Execute(cmd string, stdout io.Writer, stderr io.Writer) error {
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
	err := s.sshClient.RunCommand(command)
	return err
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

// ExecWithParams returns the results of executing the provided cmd with the
// given cmd parameters via SSH.
func (s *SSHMeta) ExecWithParams(cmd string, cmdParams []string, options ...ExecOptions) *CmdRes {
	var ops ExecOptions
	if len(options) > 0 {
		ops = options[0]
	}
	cmdStr := cmd
	if len(cmdParams) > 0 {
		for _, param := range cmdParams {
			cmdStr += fmt.Sprintf("%q ", param)
		}
	}

	log.Debugf("running command: %s", cmdStr)
	stdout := new(Buffer)
	stderr := new(Buffer)
	start := time.Now()
	err := s.Execute(cmdStr, stdout, stderr)

	res := CmdRes{
		cmd:      cmdStr,
		params:   cmdParams,
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
		}
	}

	res.SendToLog(ops.SkipLog)
	return &res
}

// Exec returns the results of executing the provided cmd via SSH.
func (s *SSHMeta) Exec(cmd string, options ...ExecOptions) *CmdRes {
	return s.ExecWithParams(cmd, nil, options...)
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

// ExecContext returns the results of running cmd via SSH in the specified
// context.
func (s *SSHMeta) ExecContext(ctx context.Context, cmd string, options ...ExecOptions) *CmdRes {
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

	res := &CmdRes{
		cmd:     cmd,
		stdout:  stdout,
		stderr:  stderr,
		success: false,
	}

	go func(res *CmdRes) {
		start := time.Now()
		if err := s.sshClient.RunCommandContext(ctx, command); err != nil {
			log.WithError(err).Error("Error running context")
		}
		res.duration = time.Since(start)
		res.SendToLog(ops.SkipLog)
	}(res)

	return res
}
