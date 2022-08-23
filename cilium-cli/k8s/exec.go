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

	"github.com/cilium/cilium-cli/internal/utils"
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

func (c *Client) execInPodWithWriters(ctx context.Context, p ExecParameters, stdout, stderr io.Writer) error {
	req := c.Clientset.CoreV1().RESTClient().Post().Resource("pods").Name(p.Pod).Namespace(p.Namespace).SubResource("exec")

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("error adding to scheme: %w", err)
	}

	parameterCodec := runtime.NewParameterCodec(scheme)

	req.VersionedParams(&corev1.PodExecOptions{
		Command:   p.Command,
		Container: p.Container,
		Stdin:     p.TTY,
		Stdout:    true,
		Stderr:    true,
		TTY:       p.TTY,
	}, parameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(c.Config, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("error while creating executor: %w", err)
	}

	var stdin io.ReadCloser
	if p.TTY {
		// CtrlCReader sends Ctrl-C/D sequence if context is cancelled
		stdin = utils.NewCtrlCReader(ctx)
		// Graceful close of stdin once we are done, no Ctrl-C is sent
		// if execution finishes before the context expires.
		defer stdin.Close()
	}

	err = exec.Stream(remotecommand.StreamOptions{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
		Tty:    p.TTY,
	})

	return err
}

func (c *Client) execInPod(ctx context.Context, p ExecParameters) (*ExecResult, error) {
	result := &ExecResult{}
	err := c.execInPodWithWriters(ctx, p, &result.Stdout, &result.Stderr)

	// TTY support may introduce "\r\n" sequences as line separators.
	// Replace them with "\n" to allow callers to not care.
	if p.TTY && bytes.Contains(result.Stdout.Bytes(), []byte("\r\n")) {
		result.Stdout = *bytes.NewBuffer(bytes.ReplaceAll(result.Stdout.Bytes(), []byte("\r\n"), []byte("\n")))
	}

	return result, err
}
