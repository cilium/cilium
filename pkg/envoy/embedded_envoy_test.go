// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
)

// To run the embedded_envoy_test, the following have to be met:
// - Environment variable `CILIUM_ENABLE_ENVOY_UNIT_TEST` must be set
// - `cilium-envoy-starter` and `cilium-envoy` must exist in the PATH
//   - if these were left running from a previous test, these must be killed
//     - `pkill -9 cilium-envoy`
// - `cilium-envoy-starter` must have capabilities CAP_NET_ADMIN and CAP_BPF
//   - e.g., `sudo setcap 'cap_net_admin,cap_bpf+pe' cilium-envoy-starter`

type EnvoySuite struct {
	tb        testing.TB
	waitGroup *completion.WaitGroup
}

func setupEnvoySuite(tb testing.TB) *EnvoySuite {
	return &EnvoySuite{
		tb: tb,
	}
}

func (s *EnvoySuite) waitForProxyCompletion() error {
	start := time.Now()
	s.tb.Log("Waiting for proxy updates to complete...")
	err := s.waitGroup.Wait()
	s.tb.Log("Wait time for proxy updates: ", time.Since(start))
	return err
}

func TestEnvoy(t *testing.T) {
	s := setupEnvoySuite(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s.waitGroup = completion.NewWaitGroup(ctx)

	if os.Getenv("CILIUM_ENABLE_ENVOY_UNIT_TEST") == "" {
		t.Skip("skipping envoy unit test; CILIUM_ENABLE_ENVOY_UNIT_TEST not set")
	}

	logging.SetLogLevelToDebug()
	flowdebug.Enable()

	testRunDir, err := os.MkdirTemp("", "envoy_go_test")
	require.NoError(t, err)

	t.Logf("run directory: %s", testRunDir)

	localEndpointStore := newLocalEndpointStore()

	logger := hivetest.Logger(t)

	xdsServer := newXDSServer(logger, nil, testipcache.NewMockIPCache(), localEndpointStore,
		xdsServerConfig{
			envoySocketDir:    GetSocketDir(testRunDir),
			proxyGID:          1337,
			httpNormalizePath: true,
		},
		nil)
	require.NotNil(t, xdsServer)

	err = xdsServer.start(t.Context())
	require.NoError(t, err)
	defer xdsServer.stop()

	accessLogServer := newAccessLogServer(logger, &proxyAccessLoggerMock{}, testRunDir, 1337, localEndpointStore, 4096)
	require.NotNil(t, accessLogServer)
	err = accessLogServer.start(t.Context())
	require.NoError(t, err)
	defer accessLogServer.stop()

	// launch debug variant of the Envoy proxy
	starter := &onDemandXdsStarter{logger: logger}
	envoyProxy, err := starter.startEmbeddedEnvoyInternal(embeddedEnvoyConfig{
		runDir:         testRunDir,
		logPath:        filepath.Join(testRunDir, "cilium-envoy.log"),
		baseID:         15,
		connectTimeout: 1,
	})
	require.NoError(t, err)
	require.NotNil(t, envoyProxy)
	t.Log("started Envoy")

	defer envoyProxy.admin.quit()

	t.Log("adding metrics listener")
	xdsServer.AddMetricsListener(9964, s.waitGroup)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	t.Log("completed adding metrics listener")
	s.waitGroup = completion.NewWaitGroup(ctx)

	t.Log("adding listener1")
	xdsServer.AddListener("listener1", policy.ParserTypeHTTP, 8081, true, false, s.waitGroup, nil)

	t.Log("adding listener2")
	xdsServer.AddListener("listener2", policy.ParserTypeHTTP, 8082, true, false, s.waitGroup, nil)

	t.Log("adding listener3")
	xdsServer.AddListener("listener3", policy.ParserTypeHTTP, 8083, false, false, s.waitGroup, nil)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	t.Log("completed adding listener1, listener2, listener3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	// Remove listener3
	t.Log("removing listener 3")
	xdsServer.RemoveListener("listener3", s.waitGroup)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	t.Log("completed removing listener 3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	// Add listener3 again
	t.Log("adding listener 3")
	var cbErr error
	cbCalled := false
	xdsServer.AddListener("listener3", "test.headerparser", 8083, false, false, s.waitGroup,
		func(err error) {
			cbCalled = true
			cbErr = err
		})

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	require.True(t, cbCalled)
	require.NoError(t, cbErr)
	t.Log("completed adding listener 3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	t.Log("stopping Envoy")
	err = envoyProxy.Stop()
	require.NoError(t, err)

	time.Sleep(2 * time.Second) // Wait for Envoy to really terminate.

	// Remove listener3 again, and wait for timeout after stopping Envoy.
	t.Log("removing listener 3")
	xdsServer.RemoveListener("listener3", s.waitGroup)
	err = s.waitForProxyCompletion()
	require.Error(t, err)
	t.Logf("failed to remove listener 3: %s", err)
}

func TestEnvoyNACK(t *testing.T) {
	s := setupEnvoySuite(t)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()

	s.waitGroup = completion.NewWaitGroup(ctx)

	if os.Getenv("CILIUM_ENABLE_ENVOY_UNIT_TEST") == "" {
		t.Skip("skipping envoy unit test; CILIUM_ENABLE_ENVOY_UNIT_TEST not set")
	}

	flowdebug.Enable()

	testRunDir, err := os.MkdirTemp("", "envoy_go_test")
	require.NoError(t, err)

	t.Logf("run directory: %s", testRunDir)

	localEndpointStore := newLocalEndpointStore()

	logger := hivetest.Logger(t)

	xdsServer := newXDSServer(logger, nil, testipcache.NewMockIPCache(), localEndpointStore,
		xdsServerConfig{
			envoySocketDir:    GetSocketDir(testRunDir),
			proxyGID:          1337,
			httpNormalizePath: true,
		}, nil)
	require.NotNil(t, xdsServer)

	err = xdsServer.start(t.Context())
	require.NoError(t, err)
	defer xdsServer.stop()

	accessLogServer := newAccessLogServer(logger, &proxyAccessLoggerMock{}, testRunDir, 1337, localEndpointStore, 4096)
	require.NotNil(t, accessLogServer)
	err = accessLogServer.start(t.Context())
	require.NoError(t, err)
	defer accessLogServer.stop()

	// launch debug variant of the Envoy proxy
	starter := &onDemandXdsStarter{logger: logger}
	envoyProxy, err := starter.startEmbeddedEnvoyInternal(embeddedEnvoyConfig{
		runDir:         testRunDir,
		logPath:        filepath.Join(testRunDir, "cilium-envoy.log"),
		baseID:         42,
		connectTimeout: 1,
	})
	require.NotNil(t, envoyProxy)
	require.NoError(t, err)
	t.Log("started Envoy")

	defer envoyProxy.admin.quit()

	rName := "listener:22"

	t.Log("adding ", rName)
	var cbErr error
	cbCalled := false
	xdsServer.AddListener(rName, policy.ParserTypeHTTP, 22, true, false, s.waitGroup,
		func(err error) {
			cbCalled = true
			cbErr = err
		})

	err = s.waitForProxyCompletion()
	require.Error(t, err)
	require.True(t, cbCalled)
	require.Equal(t, err, cbErr)
	require.EqualValues(t, &xds.ProxyError{Err: xds.ErrNackReceived, Detail: "Error adding/updating listener(s) listener:22: cannot bind '127.0.0.1:22': Address already in use\n"}, err)

	s.waitGroup = completion.NewWaitGroup(ctx)
	// Remove listener1
	t.Log("removing ", rName)
	xdsServer.RemoveListener(rName, s.waitGroup)
	err = s.waitForProxyCompletion()
	require.NoError(t, err)
}

type proxyAccessLoggerMock struct{}

func (p *proxyAccessLoggerMock) NewLogRecord(ctx context.Context, t accesslog.FlowType, ingress bool, tags ...accesslog.LogTag) (*accesslog.LogRecord, error) {
	panic("unimplemented")
}

func (p *proxyAccessLoggerMock) Log(lr *accesslog.LogRecord) {}
