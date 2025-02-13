// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"fmt"
	"io"
	"net/url"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/cilium/cilium/cilium-cli/k8s/internal"
)

type ExecParameters struct {
	Namespace string
	Pod       string
	Container string
	Command   []string
	TTY       bool // fuses stderr into stdout if 'true', needed for Ctrl-C support
}

func newExecutor(config *rest.Config, url *url.URL) (remotecommand.Executor, error) {
	execSPDY, err := remotecommand.NewSPDYExecutor(config, "POST", url)
	if err != nil {
		return nil, fmt.Errorf("error while creating SPDY executor: %w", err)
	}

	execWebsocket, err := remotecommand.NewWebSocketExecutor(config, "GET", url.String())
	if err != nil {
		return nil, fmt.Errorf("error while creating Websocket executor: %w", err)
	}

	exec, err := remotecommand.NewFallbackExecutor(execWebsocket, execSPDY, func(error) bool {
		return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
	})
	if err != nil {
		return nil, fmt.Errorf("error while creating Fallback executor: %w", err)
	}

	return exec, nil
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

	exec, err := newExecutor(c.Config, req.URL())
	if err != nil {
		return err
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
