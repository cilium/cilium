// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"fmt"
	"io"
	"os"
)

const (
	defaultReadFromByteCmd = "tail -c+%d %s"
	defaultMaxTries        = 5
)

// CopyFromPod is to copy srcFile in a given pod to local destFile with defaultMaxTries.
func (c *Client) CopyFromPod(ctx context.Context, namespace, pod, container string, srcFile, destFile string) error {
	pipe := newPipe(&CopyOptions{
		MaxTries: defaultMaxTries,
		ReadFunc: readFromPod(ctx, c, namespace, pod, container, srcFile),
	})

	outFile, err := os.OpenFile(destFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer outFile.Close()

	if _, err = io.Copy(outFile, pipe); err != nil {
		return err
	}
	return nil
}

func readFromPod(ctx context.Context, client *Client, namespace, pod, container, srcFile string) ReadFunc {
	return func(offset uint64, writer io.Writer) error {
		command := []string{"sh", "-c", fmt.Sprintf(defaultReadFromByteCmd, offset, srcFile)}
		return client.execInPodWithWriters(ctx, nil, ExecParameters{
			Namespace: namespace,
			Pod:       pod,
			Container: container,
			Command:   command,
		}, writer, writer)
	}
}
