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
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
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
	log.Debugf("done importing ssh config")
	node := nodes[vmName]
	if node == nil {
		log.Errorf("Node %s not found in ssh config", vmName)
		return nil
	}

	return &SSHMeta{
		sshClient: node.GetSSHClient(),
		rawConfig: config,
		nodeName:  vmName,
	}
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
func (s *SSHMeta) ExecWithSudo(cmd string) *CmdRes {
	command := fmt.Sprintf("sudo %s", cmd)
	return s.Exec(command)
}

// Exec returns the results of executing the provided cmd via SSH.
func (s *SSHMeta) Exec(cmd string) *CmdRes {
	log.Debugf("running command: %s", cmd)

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	exit := true
	err := s.Execute(cmd, stdout, stderr)
	if err != nil {
		exit = false
	}
	res := CmdRes{
		cmd:     cmd,
		stdout:  stdout,
		stderr:  stderr,
		success: exit,
	}
	// Set the exitCode if the error is an ExitError
	if exiterr, ok := err.(*ssh.ExitError); ok {
		res.exitcode = exiterr.Waitmsg.ExitStatus()
	}

	res.SendToLog()
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

// ExecContext returns the results of running cmd via SSH in the specified
// context.
func (s *SSHMeta) ExecContext(ctx context.Context, cmd string) *CmdRes {
	if ctx == nil {
		panic("no context provided")
	}

	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	command := &SSHCommand{
		Path:   cmd,
		Stdin:  os.Stdin,
		Stdout: stdout,
		Stderr: stderr,
	}

	res := CmdRes{
		cmd:     cmd,
		stdout:  stdout,
		stderr:  stderr,
		success: false,
	}

	go func() {
		s.sshClient.RunCommandContext(ctx, command)
		res.SendToLog()
	}()

	return &res
}
