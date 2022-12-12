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

func (c *Client) execInPodWithWriters(ctx context.Context, p ExecParameters, stdout, stderr io.Writer) error {
	req := c.Clientset.CoreV1().RESTClient().Post().Namespace(p.Namespace).Resource("pods").Name(p.Pod).SubResource("exec")

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("error adding to scheme: %w", err)
	}

	parameterCodec := runtime.NewParameterCodec(scheme)

	req.VersionedParams(&corev1.PodExecOptions{
		Command:   p.Command,
		Container: p.Container,
		Stdout:    true,
		Stderr:    true,
	}, parameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(c.Config, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("error while creating executor: %w", err)
	}

	return exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: stdout,
		Stderr: stderr,
	})
}

func (c *Client) execInPod(ctx context.Context, p ExecParameters) (*ExecResult, error) {
	result := &ExecResult{}
	err := c.execInPodWithWriters(ctx, p, &result.Stdout, &result.Stderr)
	return result, err
}
