// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	loadertypes "github.com/cilium/cilium/pkg/datapath/loader/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
	k8sClientTestutils "github.com/cilium/cilium/pkg/k8s/client/testutils"
	proxy "github.com/cilium/cilium/pkg/proxy/types"
	"github.com/cilium/cilium/pkg/time"
)

// testLoader is a minimal loadertypes.Loader implementation for testing
// HostDatapathInitialized behavior. The channel is created but never closed
// to simulate a not-yet-ready datapath. Call closeLoader() to signal readiness.
type testLoader struct {
	ch chan struct{}
}

func newTestLoader() *testLoader {
	return &testLoader{ch: make(chan struct{})}
}

// closeLoader signals that the datapath is ready.
func (f *testLoader) closeLoader() {
	close(f.ch)
}

func (f *testLoader) HostDatapathInitialized() <-chan struct{} { return f.ch }
func (f *testLoader) CallsMapPath(_ uint16) string             { return "" }
func (f *testLoader) Unload(_ endpoint.Endpoint)               {}
func (f *testLoader) ReloadDatapath(_ context.Context, _ endpoint.Endpoint, _ *config.Config, _ *metrics.SpanStat) (string, error) {
	return "", nil
}
func (f *testLoader) EndpointHash(_ endpoint.Config, _ *config.Config) (string, error) {
	return "", nil
}
func (f *testLoader) ReinitializeHostDev(_ context.Context, _ int) error { return nil }
func (f *testLoader) Reinitialize(_ context.Context, _ *config.Config, _ tunnel.Config, _ iptables.Manager, _ proxy.Proxy, _ bigtcp.Config) error {
	return nil
}
func (f *testLoader) WriteEndpointConfig(_ io.Writer, _ endpoint.Config) error {
	return nil
}

// newTestStatusCollector creates a minimal statusCollector for use in tests.
// allProbesInitialized is set to true so the switch falls through to the relevant cases.
// The fake clientset has Kubernetes disabled to avoid hitting the k8s check.
func newTestStatusCollector(t *testing.T, loader loadertypes.Loader, datapathReadyTimeout time.Duration) *statusCollector {
	t.Helper()
	logger := hivetest.Logger(t)
	config := Config{
		StatusCollectorWarningThreshold:  15 * time.Second,
		StatusCollectorFailureThreshold:  1 * time.Minute,
		StatusCollectorInterval:          5 * time.Second,
		StatusCollectorProbeCheckTimeout: 5 * time.Minute,
		StatusCollectorStackdumpPath:     "",
		DatapathReadyTimeout:             datapathReadyTimeout,
	}

	// Use a disabled fake clientset so Clientset.IsEnabled() returns false.
	fakeClientset, _ := k8sClientTestutils.NewFakeClientset(logger)
	fakeClientset.Disable()

	return &statusCollector{
		statusCollector:      newCollector(logger, config),
		allProbesInitialized: true,
		startTime:            time.Now(),
		statusParams: statusParams{
			Logger:    logger,
			Config:    config,
			Clientset: fakeClientset,
			Loader:    loader,
		},
	}
}

// TestDatapathReadiness_NotReady verifies that GetStatus returns a non-OK
// Failure state when requireDatapathReady=true and the eBPF datapath has not
// yet been initialized (channel open).
func TestDatapathReadiness_NotReady(t *testing.T) {
	loader := newTestLoader() // channel never closed = not ready

	collector := newTestStatusCollector(t, loader, 120*time.Second)
	sr := collector.GetStatus(true, false, true)

	require.NotNil(t, sr.Cilium, "expected Cilium status to be set")
	assert.Equal(t, models.StatusStateFailure, sr.Cilium.State,
		"expected Failure state when datapath not ready")
	assert.True(t, strings.Contains(strings.ToLower(sr.Cilium.Msg), "datapath"),
		"expected 'datapath' in status message, got: %q", sr.Cilium.Msg)
}

// TestDatapathReadiness_Ready verifies that GetStatus returns OK when
// requireDatapathReady=true and the eBPF datapath channel is closed.
func TestDatapathReadiness_Ready(t *testing.T) {
	loader := newTestLoader()
	loader.closeLoader() // signal datapath is ready

	collector := newTestStatusCollector(t, loader, 120*time.Second)
	sr := collector.GetStatus(true, false, true)

	require.NotNil(t, sr.Cilium, "expected Cilium status to be set")
	assert.Equal(t, models.StatusStateOk, sr.Cilium.State,
		"expected OK state when datapath is ready")
}

// TestDatapathReadiness_NotRequired verifies that GetStatus returns OK when
// requireDatapathReady=false even if the datapath is not yet initialized.
func TestDatapathReadiness_NotRequired(t *testing.T) {
	loader := newTestLoader() // not ready, but not required

	collector := newTestStatusCollector(t, loader, 120*time.Second)
	sr := collector.GetStatus(true, false, false)

	require.NotNil(t, sr.Cilium, "expected Cilium status to be set")
	assert.Equal(t, models.StatusStateOk, sr.Cilium.State,
		"expected OK state when datapath readiness not required")
}

// TestDatapathReadiness_NilLoader verifies that GetStatus treats a nil Loader
// as "datapath ready", avoiding a false unhealthy state on agents that don't
// wire up the loader (e.g. tests, non-BPF modes).
func TestDatapathReadiness_NilLoader(t *testing.T) {
	collector := newTestStatusCollector(t, nil, 120*time.Second)
	sr := collector.GetStatus(true, false, true)

	require.NotNil(t, sr.Cilium, "expected Cilium status to be set")
	assert.Equal(t, models.StatusStateOk, sr.Cilium.State,
		"expected OK state when Loader is nil")
}

// TestDatapathReadiness_TimeoutFallback verifies that once DatapathReadyTimeout
// elapses, GetStatus reports OK even if the datapath channel is still open.
// This prevents permanent node deadlock if BPF programs never load.
func TestDatapathReadiness_TimeoutFallback(t *testing.T) {
	loader := newTestLoader() // channel never closed

	logger := hivetest.Logger(t)
	config := Config{
		StatusCollectorWarningThreshold:  15 * time.Second,
		StatusCollectorFailureThreshold:  1 * time.Minute,
		StatusCollectorInterval:          5 * time.Second,
		StatusCollectorProbeCheckTimeout: 5 * time.Minute,
		StatusCollectorStackdumpPath:     "",
		DatapathReadyTimeout:             1 * time.Nanosecond, // instant timeout
	}
	fakeClientset, _ := k8sClientTestutils.NewFakeClientset(logger)
	fakeClientset.Disable()

	collector := &statusCollector{
		statusCollector:      newCollector(logger, config),
		allProbesInitialized: true,
		startTime:            time.Now().Add(-2 * time.Second), // well in the past
		statusParams: statusParams{
			Logger:    logger,
			Config:    config,
			Clientset: fakeClientset,
			Loader:    loader,
		},
	}

	sr := collector.GetStatus(true, false, true)

	require.NotNil(t, sr.Cilium, "expected Cilium status to be set")
	assert.Equal(t, models.StatusStateOk, sr.Cilium.State,
		"expected OK state after DatapathReadyTimeout elapsed")
}
