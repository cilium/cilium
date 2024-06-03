// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/policy"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
)

type EnvoySuite struct {
	waitGroup *completion.WaitGroup
}

func setupEnvoySuite(tb testing.TB) *EnvoySuite {
	return &EnvoySuite{}
}

func (s *EnvoySuite) waitForProxyCompletion() error {
	start := time.Now()
	log.Debug("Waiting for proxy updates to complete...")
	err := s.waitGroup.Wait()
	log.Debug("Wait time for proxy updates: ", time.Since(start))
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

	log.Debugf("run directory: %s", testRunDir)

	localEndpointStore := newLocalEndpointStore()

	xdsServer, err := newXDSServer(nil, testipcache.NewMockIPCache(), localEndpointStore,
		xdsServerConfig{
			envoySocketDir:    testRunDir,
			proxyGID:          1337,
			httpNormalizePath: true,
		})
	require.NotNil(t, xdsServer)
	require.NoError(t, err)

	err = xdsServer.start()
	require.NoError(t, err)
	defer xdsServer.stop()

	accessLogServer := newAccessLogServer(testRunDir, 1337, localEndpointStore)
	require.NotNil(t, accessLogServer)
	err = accessLogServer.start()
	require.NoError(t, err)
	defer accessLogServer.stop()

	// launch debug variant of the Envoy proxy
	envoyProxy, err := startEmbeddedEnvoy(embeddedEnvoyConfig{
		runDir:         testRunDir,
		logPath:        filepath.Join(testRunDir, "cilium-envoy.log"),
		baseID:         0,
		connectTimeout: 1,
	})
	require.NotNil(t, envoyProxy)
	require.NoError(t, err)
	log.Debug("started Envoy")

	log.Debug("adding metrics listener")
	xdsServer.AddMetricsListener(9964, s.waitGroup)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	log.Debug("completed adding metrics listener")
	s.waitGroup = completion.NewWaitGroup(ctx)

	log.Debug("adding listener1")
	xdsServer.AddListener("listener1", policy.ParserTypeHTTP, 8081, true, false, s.waitGroup)

	log.Debug("adding listener2")
	xdsServer.AddListener("listener2", policy.ParserTypeHTTP, 8082, true, false, s.waitGroup)

	log.Debug("adding listener3")
	xdsServer.AddListener("listener3", policy.ParserTypeHTTP, 8083, false, false, s.waitGroup)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	log.Debug("completed adding listener1, listener2, listener3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	// Remove listener3
	log.Debug("removing listener 3")
	xdsServer.RemoveListener("listener3", s.waitGroup)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	log.Debug("completed removing listener 3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	// Add listener3 again
	log.Debug("adding listener 3")
	xdsServer.AddListener("listener3", "test.headerparser", 8083, false, false, s.waitGroup)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	log.Debug("completed adding listener 3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	log.Debug("stopping Envoy")
	err = envoyProxy.Stop()
	require.NoError(t, err)

	time.Sleep(2 * time.Second) // Wait for Envoy to really terminate.

	// Remove listener3 again, and wait for timeout after stopping Envoy.
	log.Debug("removing listener 3")
	xdsServer.RemoveListener("listener3", s.waitGroup)
	err = s.waitForProxyCompletion()
	require.Error(t, err)
	log.Debugf("failed to remove listener 3: %s", err)
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

	log.Debugf("run directory: %s", testRunDir)

	localEndpointStore := newLocalEndpointStore()

	xdsServer, err := newXDSServer(nil, testipcache.NewMockIPCache(), localEndpointStore,
		xdsServerConfig{
			envoySocketDir:    testRunDir,
			proxyGID:          1337,
			httpNormalizePath: true,
		})
	require.NotNil(t, xdsServer)
	require.NoError(t, err)
	err = xdsServer.start()
	require.NoError(t, err)
	defer xdsServer.stop()

	accessLogServer := newAccessLogServer(testRunDir, 1337, localEndpointStore)
	require.NotNil(t, accessLogServer)
	err = accessLogServer.start()
	require.NoError(t, err)
	defer accessLogServer.stop()

	// launch debug variant of the Envoy proxy
	envoyProxy, err := startEmbeddedEnvoy(embeddedEnvoyConfig{
		runDir:  testRunDir,
		logPath: filepath.Join(testRunDir, "cilium-envoy.log"),
		baseID:  42,
	})
	require.NotNil(t, envoyProxy)
	require.NoError(t, err)
	log.Debug("started Envoy")

	rName := "listener:22"

	log.Debug("adding ", rName)
	xdsServer.AddListener(rName, policy.ParserTypeHTTP, 22, true, false, s.waitGroup)

	err = s.waitForProxyCompletion()
	require.Error(t, err)
	require.EqualValues(t, &xds.ProxyError{Err: xds.ErrNackReceived, Detail: "Error adding/updating listener(s) listener:22: cannot bind '[::]:22': Address already in use\n"}, err)

	s.waitGroup = completion.NewWaitGroup(ctx)
	// Remove listener1
	log.Debug("removing ", rName)
	xdsServer.RemoveListener(rName, s.waitGroup)
	err = s.waitForProxyCompletion()
	require.NoError(t, err)
}
