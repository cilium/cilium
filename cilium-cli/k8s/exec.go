// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"bytes"
	"context"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/cilium/cilium/cilium-cli/k8s/internal"
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
	TTY       bool // fuses stderr into stdout if 'true', needed for Ctrl-C support
}

func (c *Client) execInPodWithWriters(connCtx, killCmdCtx context.Context, p ExecParameters, stdout, stderr io.Writer) error {
	req := c.Clientset.CoreV1().RESTClient().Post().Resource("pods").Name(p.Pod).Namespace(p.Namespace).SubResource("exec")

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("error adding to scheme: %w", err)
	}

	parameterCodec := runtime.NewParameterCodec(scheme)

	execOpts := &corev1.PodExecOptions{
		Command:   p.Command,
		Container: p.Container,
		Stdin:     p.TTY,
		Stdout:    true,
		Stderr:    true,
		TTY:       p.TTY,
	}
	req.VersionedParams(execOpts, parameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(c.Config, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("error while creating executor: %w", err)
	}

	var stdin io.ReadCloser
	if p.TTY {
		// CtrlCReader sends Ctrl-C/D sequence if context is cancelled
		stdin = internal.NewCtrlCReader(killCmdCtx)
		// Graceful close of stdin once we are done, no Ctrl-C is sent
		// if execution finishes before the context expires.
		defer stdin.Close()
	}

	return exec.StreamWithContext(connCtx, remotecommand.StreamOptions{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
		Tty:    p.TTY,
	})
}

func (c *Client) execInPod(ctx context.Context, p ExecParameters) (*ExecResult, error) {
	result := &ExecResult{}
	if err := c.execInPodWithWriters(ctx, nil, p, &result.Stdout, &result.Stderr); err != nil {
		return result, fmt.Errorf("error with exec request (pod=%s/%s, container=%s): %w", p.Namespace, p.Pod, p.Container, err)
	}
	return result, nil
}
