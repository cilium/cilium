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

package pipeexec

import (
	"os/exec"

	"github.com/cilium/cilium/pkg/syncbytes"
)

// CommandPipe executes the slice of Cmd and redirects stdout to stdin of the
// next command. The command returns stdout and stderr of the last command or
// the first command that fails
func CommandPipe(cmds []*exec.Cmd) ([]byte, []byte, error) {
	// We need atleast one command to pipe.
	if len(cmds) < 1 {
		return nil, nil, nil
	}

	// Total output of commands.
	var output, stderr syncbytes.Buffer

	lastCmd := len(cmds) - 1
	for i, cmd := range cmds[:lastCmd] {
		var err error
		// We need to connect every command's stdin to the previous command's stdout
		if cmds[i+1].Stdin, err = cmd.StdoutPipe(); err != nil {
			return nil, nil, err
		}
		// We need to connect each command's stderr to a buffer
		cmd.Stderr = &stderr
	}

	// Connect the output and error for the last command
	cmds[lastCmd].Stdout, cmds[lastCmd].Stderr = &output, &stderr

	// Let's start each command
	for _, cmd := range cmds {
		if err := cmd.Start(); err != nil {
			return output.Bytes(), stderr.Bytes(), err
		}
	}

	// We wait for each command to complete
	for _, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			return output.Bytes(), stderr.Bytes(), err
		}
	}

	// Return the output and the standard error
	return output.Bytes(), stderr.Bytes(), nil
}
