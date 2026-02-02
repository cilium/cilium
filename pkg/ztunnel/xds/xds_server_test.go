// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/ztunnel/table"
)

func TestNewServer(t *testing.T) {
	t.Run("creates server with correct fields", func(t *testing.T) {
		log := slog.New(slog.DiscardHandler)
		db := statedb.New()
		tbl, err := table.NewEnrolledNamespacesTable(db)
		require.NoError(t, err)

		socketPath := "/tmp/test-xds.sock"

		server := newServer(log, db, nil, tbl, socketPath, NewMetrics())

		require.NotNil(t, server)
		require.Equal(t, log, server.log)
		require.Equal(t, db, server.db)
		require.Equal(t, tbl, server.enrolledNamespaceTable)
		require.Equal(t, socketPath, server.xdsUnixAddr)
		require.NotNil(t, server.endpointEventChan)
		require.Equal(t, 1024, cap(server.endpointEventChan))
	})
}

func TestServerServe(t *testing.T) {
	t.Run("starts and listens on unix socket", func(t *testing.T) {
		// Create temp directory for socket
		tmpDir, err := os.MkdirTemp("", "xds-test-*")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		socketPath := filepath.Join(tmpDir, "xds.sock")

		log := slog.New(slog.DiscardHandler)
		db := statedb.New()
		tbl, err := table.NewEnrolledNamespacesTable(db)
		require.NoError(t, err)

		server := newServer(log, db, nil, tbl, socketPath, NewMetrics())

		// Start the server
		err = server.Serve()
		require.NoError(t, err)
		defer server.GracefulStop()

		// Verify socket file exists
		_, err = os.Stat(socketPath)
		require.NoError(t, err, "Socket file should exist")

		// Verify we can connect to it
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		conn, err := grpc.DialContext(ctx, "unix://"+socketPath,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock())
		require.NoError(t, err, "Should be able to connect to server")
		defer conn.Close()
	})

	t.Run("removes existing socket file", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "xds-test-*")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		socketPath := filepath.Join(tmpDir, "xds.sock")

		// Create a regular file at socket path
		f, err := os.Create(socketPath)
		require.NoError(t, err)
		f.Close()

		log := slog.New(slog.DiscardHandler)
		db := statedb.New()
		tbl, err := table.NewEnrolledNamespacesTable(db)
		require.NoError(t, err)

		server := newServer(log, db, nil, tbl, socketPath, NewMetrics())

		// Should succeed even with existing file
		err = server.Serve()
		require.NoError(t, err)
		defer server.GracefulStop()

		// Verify socket works
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		conn, err := grpc.DialContext(ctx, "unix://"+socketPath,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock())
		require.NoError(t, err)
		defer conn.Close()
	})

	t.Run("fails on invalid socket path", func(t *testing.T) {
		// Use a path in a non-existent directory
		socketPath := "/nonexistent/directory/xds.sock"

		log := slog.New(slog.DiscardHandler)
		db := statedb.New()
		tbl, err := table.NewEnrolledNamespacesTable(db)
		require.NoError(t, err)

		server := newServer(log, db, nil, tbl, socketPath, NewMetrics())

		err = server.Serve()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to listen on unix socket")
	})
}

func TestServerGracefulStop(t *testing.T) {
	t.Run("stops server gracefully", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "xds-test-*")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		socketPath := filepath.Join(tmpDir, "xds.sock")

		log := slog.New(slog.DiscardHandler)
		db := statedb.New()
		tbl, err := table.NewEnrolledNamespacesTable(db)
		require.NoError(t, err)

		server := newServer(log, db, nil, tbl, socketPath, NewMetrics())

		err = server.Serve()
		require.NoError(t, err)

		// Connect to server
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		conn, err := grpc.DialContext(ctx, "unix://"+socketPath,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock())
		require.NoError(t, err)

		// Stop server
		server.GracefulStop()

		// Connection should now fail for new requests
		conn.Close()

		// Try to connect again - should fail
		ctx2, cancel2 := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel2()

		_, err = grpc.DialContext(ctx2, "unix://"+socketPath,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock())
		require.Error(t, err, "Connection should fail after server stop")
	})
}

func TestStreamAggregatedResources(t *testing.T) {
	t.Run("returns unimplemented error", func(t *testing.T) {
		log := slog.New(slog.DiscardHandler)
		db := statedb.New()
		tbl, err := table.NewEnrolledNamespacesTable(db)
		require.NoError(t, err)

		server := newServer(log, db, nil, tbl, "/tmp/test.sock", NewMetrics())

		mockStream := &MockStreamAggregatedResourcesServer{}

		err = server.StreamAggregatedResources(mockStream)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unimplemented")
	})
}

func TestDeltaAggregatedResources(t *testing.T) {
	t.Run("returns immediately on canceled context", func(t *testing.T) {
		log := slog.New(slog.DiscardHandler)
		db := statedb.New()
		tbl, err := table.NewEnrolledNamespacesTable(db)
		require.NoError(t, err)

		server := newServer(log, db, nil, tbl, "/tmp/test.sock", NewMetrics())

		// Create canceled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		mockStream := &MockStream{}
		mockStream.OnContext = func() context.Context {
			return ctx
		}

		err = server.DeltaAggregatedResources(mockStream)
		require.Error(t, err)
		require.Equal(t, context.Canceled, err)
	})

	t.Run("stops when context is canceled", func(t *testing.T) {
		log := slog.New(slog.DiscardHandler)
		db := statedb.New()
		tbl, err := table.NewEnrolledNamespacesTable(db)
		require.NoError(t, err)

		server := newServer(log, db, nil, tbl, "/tmp/test.sock", NewMetrics())

		// Create a context that we'll cancel
		ctx, cancel := context.WithCancel(context.Background())

		mockStream := &MockStream{}
		mockStream.OnContext = func() context.Context {
			return ctx
		}
		// Provide a Recv function that blocks until context is canceled
		mockStream._Recv = func() (*v3.DeltaDiscoveryRequest, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}

		// Start DeltaAggregatedResources in goroutine since it blocks
		done := make(chan error, 1)
		go func() {
			done <- server.DeltaAggregatedResources(mockStream)
		}()

		// Give it a moment to start
		time.Sleep(50 * time.Millisecond)

		// Cancel context to stop the stream
		cancel()

		// Wait for completion
		select {
		case err := <-done:
			require.Error(t, err)
			require.Equal(t, context.Canceled, err)
		case <-time.After(2 * time.Second):
			t.Fatal("DeltaAggregatedResources did not return in time")
		}
	})
}

func TestEndpointEventChannel(t *testing.T) {
	t.Run("endpoint event channel is accessible", func(t *testing.T) {
		log := slog.New(slog.DiscardHandler)
		db := statedb.New()
		tbl, err := table.NewEnrolledNamespacesTable(db)
		require.NoError(t, err)

		server := newServer(log, db, nil, tbl, "/tmp/test.sock", NewMetrics())

		// Channel should be writable
		event := &EndpointEvent{
			Type: CREATE,
		}

		select {
		case server.endpointEventChan <- event:
			// Success
		default:
			t.Fatal("Should be able to write to endpoint event channel")
		}

		// Channel should be readable
		select {
		case received := <-server.endpointEventChan:
			require.Equal(t, CREATE, received.Type)
		default:
			t.Fatal("Should be able to read from endpoint event channel")
		}
	})
}

// MockStreamAggregatedResourcesServer implements v3.AggregatedDiscoveryService_StreamAggregatedResourcesServer
var _ v3.AggregatedDiscoveryService_StreamAggregatedResourcesServer = (*MockStreamAggregatedResourcesServer)(nil)

type MockStreamAggregatedResourcesServer struct {
	testutils.FakeGRPCServerStream
}

func (s *MockStreamAggregatedResourcesServer) Send(*v3.DiscoveryResponse) error {
	return nil
}

func (s *MockStreamAggregatedResourcesServer) Recv() (*v3.DiscoveryRequest, error) {
	return nil, nil
}
