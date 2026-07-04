// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics_test

import (
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/metrics"
)

// newTestHive builds a hive carrying a Registry wired to a real job.Group
// (via job.Cell), with AddServerRuntimeHooks called for the given address
// before the hive starts, so the OneShot job is queued rather than run
// immediately. RegistryParams has no Shutdowner field to spy on directly -
// job.WithShutdown() pulls the hive's own Shutdowner via the job registry -
// so tests drive the real hive.Run() and observe whether it self-terminates.
func newTestHive(t *testing.T, addr string) *hive.Hive {
	t.Helper()
	log := hivetest.Logger(t)

	return hive.New(
		job.Cell,
		cell.Invoke(func(jr job.Registry, lifecycle cell.Lifecycle) {
			health, _ := cell.NewSimpleHealth()
			group := jr.NewGroup(health)
			reg := metrics.NewRegistry(metrics.RegistryParams{
				Logger:    log,
				Lifecycle: lifecycle,
				JobGroup:  group,
				Config:    metrics.RegistryConfig{PrometheusServeAddr: addr},
			})
			reg.AddServerRuntimeHooks("test-prometheus-server", nil, net.ListenConfig{})
		}),
	)
}

// TestAddServerRuntimeHooksListenFailureDoesNotShutdownHive is a
// regression test: previously, a failure to bind the prometheus metrics
// address (e.g. EADDRINUSE from a stale process) called
// Shutdowner.Shutdown() via job.WithShutdown(), taking down the whole
// agent/operator for a non-critical metrics endpoint. The error must now
// just be logged.
func TestAddServerRuntimeHooksListenFailureDoesNotShutdownHive(t *testing.T) {
	// Occupy the port first so the registry's own Listen() call fails.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer blocker.Close()
	addr := blocker.Addr().String()

	log := hivetest.Logger(t)
	h := newTestHive(t, addr)

	runDone := make(chan error, 1)
	go func() { runDone <- h.Run(log) }()

	selfTerminated := false
	select {
	case <-runDone:
		selfTerminated = true
	case <-time.After(2 * time.Second):
		// Still running after the OneShot's error path had time to fire -
		// good. Shut it down ourselves so the test can finish.
		h.Shutdown()
		<-runDone
	}

	require.False(t, selfTerminated, "a listen failure must not shut down the hive")
}

// TestAddServerRuntimeHooksServesMetrics is a baseline check that the
// happy path still works: the server binds and serves /metrics.
func TestAddServerRuntimeHooksServesMetrics(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	log := hivetest.Logger(t)
	h := newTestHive(t, addr)

	runDone := make(chan error, 1)
	go func() { runDone <- h.Run(log) }()
	t.Cleanup(func() {
		h.Shutdown()
		<-runDone
	})

	var resp *http.Response
	require.Eventually(t, func() bool {
		var getErr error
		resp, getErr = http.Get(fmt.Sprintf("http://%s/metrics", addr))
		return getErr == nil
	}, 2*time.Second, 20*time.Millisecond, "metrics server never became reachable")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}
