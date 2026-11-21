// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cilium/cilium/pkg/lock"
)

// newUnresponsiveAPIServer returns the address of a server that accepts
// connections but never answers, like an API server proxying to an
// unresponsive kubelet.
func newUnresponsiveAPIServer(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var (
		mu    lock.Mutex
		conns []net.Conn
	)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()

	// Closing the connections unblocks the exec abandoned by the client.
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	})

	return ln.Addr().String()
}

func TestExecInPodHonorsContext(t *testing.T) {
	config := &rest.Config{Host: "http://" + newUnresponsiveAPIServer(t)}
	clientset, err := kubernetes.NewForConfig(config)
	require.NoError(t, err)
	client := &Client{Clientset: clientset, Config: config}

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := client.ExecInPod(ctx, "kube-system", "cilium-1", "cilium-agent", []string{"true"})
		errCh <- err
	}()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(10 * time.Second):
		t.Fatal("ExecInPod did not return after its context expired")
	}
}

func TestDetachableWriter(t *testing.T) {
	var buf bytes.Buffer
	w := newDetachableWriter(&buf)
	require.Equal(t, io.Writer(w), w.writer())

	_, err := w.Write([]byte("before"))
	require.NoError(t, err)

	w.detach()
	_, err = w.Write([]byte("after"))
	require.ErrorIs(t, err, io.ErrClosedPipe)
	require.Equal(t, "before", buf.String())

	require.Nil(t, newDetachableWriter(nil).writer())
}
