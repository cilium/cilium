/*
Copyright The ORAS Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package executer is an abstraction for the docker credential helper protocol
// binaries. It is used by nativeStore to interact with installed binaries.
package executer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"

	"oras.land/oras-go/v2/registry/remote/credentials/trace"
)

// dockerDesktopHelperName is the name of the docker credentials helper
// execuatable.
const dockerDesktopHelperName = "docker-credential-desktop.exe"

// Executer is an interface that simulates an executable binary.
type Executer interface {
	Execute(ctx context.Context, input io.Reader, action string) ([]byte, error)
}

// executable implements the Executer interface.
type executable struct {
	name string
}

// New returns a new Executer instance.
func New(name string) Executer {
	return &executable{
		name: name,
	}
}

// Execute operates on an executable binary and supports context.
func (c *executable) Execute(ctx context.Context, input io.Reader, action string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.name, action)
	cmd.Stdin = input
	cmd.Stderr = os.Stderr
	trace := trace.ContextExecutableTrace(ctx)
	if trace != nil && trace.ExecuteStart != nil {
		trace.ExecuteStart(c.name, action)
	}
	output, err := cmd.Output()
	if trace != nil && trace.ExecuteDone != nil {
		trace.ExecuteDone(c.name, action, err)
	}
	if err != nil {
		switch execErr := err.(type) {
		case *exec.ExitError:
			if errMessage := string(bytes.TrimSpace(output)); errMessage != "" {
				return nil, errors.New(errMessage)
			}
		case *exec.Error:
			// check if the error is caused by Docker Desktop not running
			if execErr.Err == exec.ErrNotFound && c.name == dockerDesktopHelperName {
				return nil, errors.New("credentials store is configured to `desktop.exe` but Docker Desktop seems not running")
			}
		}
		return nil, err
	}
	return output, nil
}
