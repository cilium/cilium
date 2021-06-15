// Copyright 2020 Authors of Cilium
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

package k8s

import (
	"bytes"
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/internal/utils"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/remotecommand"
)

type ExecResult struct {
	Stdout bytes.Buffer
	Stderr bytes.Buffer
}

type ExecParameters struct {
	Namespace string
	Pod       string
	Container string
	Command   []string
}

func (c *Client) execInPod(ctx context.Context, p ExecParameters) (*ExecResult, error) {
	req := c.Clientset.CoreV1().RESTClient().Post().Resource("pods").Name(p.Pod).Namespace(p.Namespace).SubResource("exec")

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("error adding to scheme: %w", err)
	}

	parameterCodec := runtime.NewParameterCodec(scheme)

	req.VersionedParams(&corev1.PodExecOptions{
		Command:   p.Command,
		Container: p.Container,
		Stdin:     true,
		Stdout:    true,
		Stderr:    true,
		TTY:       true,
	}, parameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(c.Config, "POST", req.URL())
	if err != nil {
		return nil, fmt.Errorf("error while creating executor: %w", err)
	}
	result := &ExecResult{}

	// CtrlCReader sends Ctrl-C/D sequence if context is cancelled
	stdin := utils.NewCtrlCReader(ctx)
	// Graceful close of stdin once we are done, no Ctrl-C is sent
	// if execution finishes before the context expires.
	defer stdin.Close()

	err = exec.Stream(remotecommand.StreamOptions{
		Stdin:  stdin,
		Stdout: &result.Stdout,
		Stderr: &result.Stderr,
		Tty:    true,
	})

	// Replace "\r\n" sequences in stdout with "\n"
	if bytes.Contains(result.Stdout.Bytes(), []byte("\r\n")) {
		result.Stdout = *bytes.NewBuffer(bytes.ReplaceAll(result.Stdout.Bytes(), []byte("\r\n"), []byte("\n")))
	}

	return result, err
}
