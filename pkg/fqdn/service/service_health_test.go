// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

type listenConfigFunc func(context.Context, string, string) (net.Listener, error)

func (f listenConfigFunc) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return f(ctx, network, address)
}

func TestListenAndServeHealthOnBindFailure(t *testing.T) {
	bindErr := errors.New("address already in use")
	server := &FQDNDataServer{
		grpcServer: grpc.NewServer(),
		log:        hivetest.Logger(t),
		listener: listenConfigFunc(func(context.Context, string, string) (net.Listener, error) {
			return nil, bindErr
		}),
	}
	health, state := cell.NewSimpleHealth()

	require.ErrorIs(t, server.ListenAndServe(t.Context(), health), bindErr)
	require.False(t, server.IsReady())
	state.Lock()
	defer state.Unlock()
	require.NotEqual(t, cell.StatusOK, state.Level, "a failed bind must never report a healthy server")
}

func TestListenAndServeOccupiedPort(t *testing.T) {
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	server := &FQDNDataServer{
		grpcServer: grpc.NewServer(),
		log:        hivetest.Logger(t),
		port:       listener.Addr().(*net.TCPAddr).Port,
		listener:   newDefaultListener(),
	}
	health, state := cell.NewSimpleHealth()

	require.Error(t, server.ListenAndServe(t.Context(), health))
	require.False(t, server.IsReady())
	state.Lock()
	defer state.Unlock()
	require.NotEqual(t, cell.StatusOK, state.Level)
}

func TestListenAndServeReadinessLifecycle(t *testing.T) {
	for _, serveFailure := range []bool{false, true} {
		scenario := "shutdown"
		if serveFailure {
			scenario = "serve failure"
		}
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			listener := bufconn.Listen(1024)
			t.Cleanup(func() { listener.Close() })
			binding := make(chan struct{})
			releaseBind := make(chan struct{})
			server := &FQDNDataServer{
				grpcServer: grpc.NewServer(),
				log:        hivetest.Logger(t),
				listener: listenConfigFunc(func(ctx context.Context, _, _ string) (net.Listener, error) {
					close(binding)
					select {
					case <-releaseBind:
						return listener, nil
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}),
			}
			t.Cleanup(server.Stop)
			health, state := cell.NewSimpleHealth()
			done := make(chan error, 1)
			go func() { done <- server.ListenAndServe(ctx, health) }()
			<-binding

			require.False(t, server.IsReady(), "an unbound listener must not be ready")
			state.Lock()
			level := state.Level
			state.Unlock()
			require.NotEqual(t, cell.StatusOK, level)

			close(releaseBind)
			require.Eventually(t, server.IsReady, time.Second, time.Millisecond)
			if serveFailure {
				require.NoError(t, listener.Close())
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if serveFailure {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
			case <-time.After(time.Second):
				t.Fatal("server did not stop")
			}
			require.False(t, server.IsReady())
		})
	}
}

func TestListenAndServeReadinessAfterBindRetry(t *testing.T) {
	listener := bufconn.Listen(1024)
	t.Cleanup(func() { listener.Close() })
	bindErr := errors.New("address already in use")
	attempts := 0
	server := &FQDNDataServer{
		grpcServer: grpc.NewServer(),
		log:        hivetest.Logger(t),
		listener: listenConfigFunc(func(context.Context, string, string) (net.Listener, error) {
			attempts++
			if attempts == 1 {
				return nil, bindErr
			}
			return listener, nil
		}),
	}
	t.Cleanup(server.Stop)
	health, _ := cell.NewSimpleHealth()
	require.ErrorIs(t, server.ListenAndServe(t.Context(), health), bindErr)
	require.False(t, server.IsReady())

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe(ctx, health) }()
	require.Eventually(t, server.IsReady, time.Second, time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("server did not stop after retry")
	}
	require.False(t, server.IsReady())
}

func TestDisabledServerReadiness(t *testing.T) {
	var server *FQDNDataServer
	require.True(t, server.IsReady())
}
