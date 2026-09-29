// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthserver

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/require"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
)

// captureGroup records how many jobs were added without running them, so
// tests can drive serveListener directly.
type captureGroup struct{ added int }

func (g *captureGroup) Add(...job.Job)                { g.added++ }
func (g *captureGroup) Scoped(string) job.ScopedGroup { return g }

func newTestHealthServer() *healthServer {
	return &healthServer{
		params: healthServerParams{
			Jobs: &captureGroup{},
			Log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		serverByPort:  map[uint16]*httpHealthServer{},
		portByService: map[lb.ServiceName]uint16{},
	}
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func newHTTPHealthServer(name string) *httpHealthServer {
	return &httpHealthServer{name: lb.NewServiceName("default", name)}
}

// canBind reports whether port is currently bindable.
func canBind(port uint16) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// Regression test for #47024: a listener job that lost its registration
// (its server was replaced by a recreated service) must exit instead of
// competing for the bind and retrying "address already in use" forever.
func TestServeListenerStaleJobDoesNotBind(t *testing.T) {
	s := newTestHealthServer()
	port := freePort(t)

	current := newHTTPHealthServer("web-new")
	s.serverByPort[port] = current

	stale := newHTTPHealthServer("web-old")
	stale.Server.Addr = fmt.Sprintf(":%d", port)

	err := s.serveListener(context.Background(), stale, port)
	require.NoError(t, err, "stale job must exit cleanly so the job framework stops retrying it")
	require.True(t, canBind(port), "stale job must not have bound the port")
}

// Same as above but for the delete path: removeListener already ran, so the
// port is unowned. A stale retry must still not rebind it.
func TestServeListenerRemovedJobDoesNotBind(t *testing.T) {
	s := newTestHealthServer()
	port := freePort(t)

	removed := newHTTPHealthServer("web-gone")
	removed.Server.Addr = fmt.Sprintf(":%d", port)

	err := s.serveListener(context.Background(), removed, port)
	require.NoError(t, err)
	require.True(t, canBind(port), "removed server must not rebind the port")
}

// While the server is still registered, a bind failure must surface so the
// job framework keeps retrying: the port may be freed later and the service
// is still supposed to have a health listener.
func TestServeListenerRegisteredJobSurfacesBindError(t *testing.T) {
	s := newTestHealthServer()
	port := freePort(t)

	// Occupy the port with an unrelated listener.
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	require.NoError(t, err)
	defer ln.Close()

	srv := newHTTPHealthServer("web")
	srv.Server.Addr = fmt.Sprintf(":%d", port)
	s.serverByPort[port] = srv

	err = s.serveListener(context.Background(), srv, port)
	require.Error(t, err, "registered listener must keep surfacing bind errors for retry")
	require.ErrorContains(t, err, "address already in use")
}

// The registered listener binds, serves, and shuts down cleanly when
// removeListener runs.
func TestServeListenerServesUntilRemoved(t *testing.T) {
	s := newTestHealthServer()
	port := freePort(t)

	srv := newHTTPHealthServer("web")
	srv.Server.Addr = fmt.Sprintf(":%d", port)
	s.serverByPort[port] = srv

	done := make(chan error, 1)
	go func() {
		done <- s.serveListener(context.Background(), srv, port)
	}()

	// Wait for the listener to accept connections.
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf(":%d", port), 50*time.Millisecond)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, 5*time.Second, 20*time.Millisecond, "listener never came up")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.removeListener(ctx, port)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("listener job did not stop after removeListener")
	}

	require.Empty(t, s.serverByPort)
}

// addListener must register the server in serverByPort before the job can
// run: the job refuses to bind an unregistered server, so registering late
// would make every new listener exit immediately without ever serving.
func TestAddListenerRegistersBeforeStartingJob(t *testing.T) {
	s := newTestHealthServer()
	port := freePort(t)

	svc := &lb.Service{Name: lb.NewServiceName("default", "web")}
	s.addListener(svc, port)

	s.mu.Lock()
	srv, ok := s.serverByPort[port]
	s.mu.Unlock()
	require.True(t, ok, "server must be registered before its job starts")
	require.Equal(t, 1, s.params.Jobs.(*captureGroup).added)

	// The job started against this registration binds successfully.
	done := make(chan error, 1)
	go func() {
		done <- s.serveListener(context.Background(), srv, port)
	}()
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf(":%d", port), 50*time.Millisecond)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, 5*time.Second, 20*time.Millisecond, "listener never came up")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.removeListener(ctx, port)
	require.NoError(t, <-done)
}
