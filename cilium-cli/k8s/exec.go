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
	var errWebsocket, errSPDY error

	// We cannot control if errors from these constructors are due to lack of server support.
	// In the case of such errors, ignore them and later chose which executor to return.
	execWebsocket, errWebsocket := remotecommand.NewWebSocketExecutor(config, "GET", url.String())
	execSPDY, errSPDY := remotecommand.NewSPDYExecutor(config, "POST", url)

	// NewFallBackExecutor returns a remotecommand.Executor which attempts
	// a connection with a primry executor and a secondary executor.
	// However, it does this by calling a method on both the primary and
	// secondary executors passed to it. This means that both of them must
	// not be nil if we want to avoid a crash. Therefore, if one of them
	// encountered an error, return the other one.
	if errSPDY != nil && errWebsocket == nil {
		return execWebsocket, nil
	}
	if errWebsocket != nil && errSPDY == nil {
		return execSPDY, nil
	}

	if errSPDY != nil && errWebsocket != nil {
		return nil, fmt.Errorf("Error while creating k8s executor: (websocket) %w, (spdy) %w", errWebsocket, errSPDY)
	}

	// Default to the SPDY connection
	execFallback, errFallback := remotecommand.NewFallbackExecutor(execSPDY, execWebsocket, func(err error) bool {
		return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
	})
	if errFallback != nil {
		return nil, fmt.Errorf("Error while creating k8s executor: %w", errFallback)
	}

	return execFallback, nil
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
