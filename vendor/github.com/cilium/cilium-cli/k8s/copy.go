// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	defaultReadFromByteCmd = "tail -c+%d %s"
)

// CopyFromPod is to copy srcFile in a given pod to local destFile with defaultMaxTries.
func (c *Client) CopyFromPod(ctx context.Context, namespace, pod, container, fromFile, destFile string, retryLimit int) error {

	// attempt to get the size of the file
	fileSize := uint64(0)
	sizeCmd := []string{"stat", "-c", "%s", fromFile}
	if res, err := c.ExecInPod(ctx, namespace, pod, container, sizeCmd); err == nil {
		sizeStr := strings.TrimSuffix(res.String(), "\n")
		if s, err := strconv.ParseUint(sizeStr, 10, 64); err == nil {
			fileSize = s
		}
	}

	pipe := newPipe(&CopyOptions{
		MaxTries: retryLimit,
		ReadFunc: readFromPod(ctx, c, namespace, pod, container, fromFile, fileSize),
	})

	outFile, err := os.OpenFile(destFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, pipe)
	return err
}

type countWriter struct {
	total uint64
	w     io.Writer
}

func (l *countWriter) Write(p []byte) (int, error) {
	n, err := l.w.Write(p)
	l.total += uint64(n)
	return n, err
}

func readFromPod(ctx context.Context, client *Client, namespace, pod, container, srcFile string, srcFileSize uint64) ReadFunc {

	return func(offset uint64, writer io.Writer) error {
		command := []string{"sh", "-c", fmt.Sprintf(defaultReadFromByteCmd, offset, srcFile)}
		outw := &countWriter{w: writer}
		ret := client.execInPodWithWriters(ctx, nil, ExecParameters{
			Namespace: namespace,
			Pod:       pod,
			Container: container,
			Command:   command,
		}, outw, writer)

		// if the read command was a success and we know the size of the source file, check
		// whether we have read everything.
		if ret == nil && srcFileSize > 0 {
			if offset+outw.total < srcFileSize {
				ret = fmt.Errorf("incomplete read: read %d from %s", offset+outw.total, srcFile)
			}
		}
		return ret
	}
}
