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
)

//Node contains metadata about Vagrant boxes used for running tests
type Node struct {
	sshClient *SSHClient
	host      string
	port      int
	env       []string
}

//CreateNode returns a Node with the specified host, port, and user.
func CreateNode(host string, port int, user string) *Node {
	return &Node{
		host:      host,
		port:      port,
		sshClient: GetSSHclient(host, port, user),
	}
}

//CreateNodeFromTarget returns a Node initialized based on the provided SSH-config target
func CreateNodeFromTarget(target string) *Node {
	var vagrant Vagrant
	config, err := vagrant.GetSSHConfig(target)
	if err != nil {
		return nil
	}
	nodes, err := ImportSSHconfig(config)
	if err != nil {
		return nil
	}
	node := nodes[target]
	if node == nil {
		return nil
	}

	return &Node{
		host:      node.host,
		port:      node.port,
		sshClient: node.GetSSHClient(),
	}
}

//Execute executes cmd on the provided node and stores the stdout / stderr of
//the command in the provided buffers. Returns false if the command failed
//during its execution.
func (node *Node) Execute(cmd string, stdout io.Writer, stderr io.Writer) bool {
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
	err := node.sshClient.RunCommand(command)
	if err != nil {
		return false
	}
	return true
}

//ExecWithSudo executes the provided command using sudo privileges. The stdout
//and stderr of the command are written to the specified stdout / stderr
//buffers accordingly. Returns false if execution of cmd failed.
func (node *Node) ExecWithSudo(cmd string, stdout io.Writer, stderr io.Writer) bool {
	command := fmt.Sprintf("sudo %s", cmd)
	return node.Execute(command, stdout, stderr)
}

//Exec executes the provided cmd and returns metadata about its result in CmdRes
func (node *Node) Exec(cmd string) *CmdRes {
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	exit := node.Execute(cmd, stdout, stderr)

	return &CmdRes{
		cmd:    cmd,
		stdout: stdout,
		stderr: stderr,
		exit:   exit,
	}
}

//ExecContext run a command in background and stop when cancel the context
func (node *Node) ExecContext(ctx context.Context, cmd string) *CmdRes {
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
	go func() {
		node.sshClient.RunCommandContext(ctx, command)
	}()
	return &CmdRes{
		cmd:    cmd,
		stdout: stdout,
		stderr: stderr,
		exit:   false,
	}
}
