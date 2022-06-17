// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package e2ehelpers

import (
	"bytes"
	"context"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/e2e-framework/klient"
)

func ExecInPod(ctx context.Context, client klient.Client, namespace, pod, container string, stdout, stderr io.Writer, command ...string) error {
	restClient, err := rest.RESTClientFor(client.RESTConfig())
	if err != nil {
		return err
	}

	req := restClient.Post().Resource("pods").Name(pod).Namespace(namespace).SubResource("exec")

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("error adding to scheme: %w", err)
	}

	parameterCodec := runtime.NewParameterCodec(scheme)

	req.VersionedParams(&corev1.PodExecOptions{
		Command:   command,
		Container: container,
		Stdout:    true,
		Stderr:    true,
	}, parameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(client.RESTConfig(), "POST", req.URL())
	if err != nil {
		return fmt.Errorf("error while creating executor: %w", err)
	}

	return exec.Stream(remotecommand.StreamOptions{
		Stdout: stdout,
		Stderr: stderr,
	})
}

func ExecInPodCombinedOutput(ctx context.Context, client klient.Client, namespace, pod, container string, command ...string) ([]byte, error) {
	combinedOutput := &bytes.Buffer{}
	err := ExecInPod(ctx, client, namespace, pod, container, combinedOutput, combinedOutput)
	return combinedOutput.Bytes(), err
}

func ExecInPodOutput(ctx context.Context, client klient.Client, namespace, pod, container string, command ...string) ([]byte, error) {
	output := &bytes.Buffer{}
	err := ExecInPod(ctx, client, namespace, pod, container, output, io.Discard)
	return output.Bytes(), err
}
