// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/spf13/viper"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type EnvoySuite struct {
	waitGroup *completion.WaitGroup
}

var _ = Suite(&EnvoySuite{})

func (s *EnvoySuite) waitForProxyCompletion() error {
	start := time.Now()
	log.Debug("Waiting for proxy updates to complete...")
	err := s.waitGroup.Wait()
	log.Debug("Wait time for proxy updates: ", time.Since(start))
	return err
}

func (s *EnvoySuite) TestEnvoy(c *C) {
	option.Config.Populate(viper.GetViper())
	option.Config.ProxyConnectTimeout = 1
	c.Assert(option.Config.ProxyConnectTimeout, Not(Equals), 0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s.waitGroup = completion.NewWaitGroup(ctx)

	if os.Getenv("CILIUM_ENABLE_ENVOY_UNIT_TEST") == "" {
		c.Skip("skipping envoy unit test; CILIUM_ENABLE_ENVOY_UNIT_TEST not set")
	}

	logging.SetLogLevelToDebug()
	flowdebug.Enable()

	testRunDir, err := os.MkdirTemp("", "envoy_go_test")
	c.Assert(err, IsNil)

	log.Debugf("run directory: %s", testRunDir)

	xdsServer := StartXDSServer(testipcache.NewMockIPCache(), testRunDir)
	defer xdsServer.stop()
	StartAccessLogServer(testRunDir, xdsServer)

	// launch debug variant of the Envoy proxy
	envoyProxy := StartEmbeddedEnvoy(testRunDir, filepath.Join(testRunDir, "cilium-envoy.log"), 0)
	c.Assert(envoyProxy, NotNil)
	log.Debug("started Envoy")

	log.Debug("adding metrics listener")
	xdsServer.AddMetricsListener(9964, s.waitGroup)

	err = s.waitForProxyCompletion()
	c.Assert(err, IsNil)
	log.Debug("completed adding metrics listener")
	s.waitGroup = completion.NewWaitGroup(ctx)

	log.Debug("adding listener1")
	xdsServer.AddListener("listener1", policy.ParserTypeHTTP, 8081, true, false, s.waitGroup)

	log.Debug("adding listener2")
	xdsServer.AddListener("listener2", policy.ParserTypeHTTP, 8082, true, false, s.waitGroup)

	log.Debug("adding listener3")
	xdsServer.AddListener("listener3", policy.ParserTypeHTTP, 8083, false, false, s.waitGroup)

	err = s.waitForProxyCompletion()
	c.Assert(err, IsNil)
	log.Debug("completed adding listener1, listener2, listener3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	// Remove listener3
	log.Debug("removing listener 3")
	xdsServer.RemoveListener("listener3", s.waitGroup)

	err = s.waitForProxyCompletion()
	c.Assert(err, IsNil)
	log.Debug("completed removing listener 3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	// Add listener3 again
	log.Debug("adding listener 3")
	xdsServer.AddListener("listener3", policy.L7ParserType("test.headerparser"), 8083, false, false, s.waitGroup)

	err = s.waitForProxyCompletion()
	c.Assert(err, IsNil)
	log.Debug("completed adding listener 3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	log.Debug("stopping Envoy")
	err = envoyProxy.Stop()
	c.Assert(err, IsNil)

	time.Sleep(2 * time.Second) // Wait for Envoy to really terminate.

	// Remove listener3 again, and wait for timeout after stopping Envoy.
	log.Debug("removing listener 3")
	xdsServer.RemoveListener("listener3", s.waitGroup)
	err = s.waitForProxyCompletion()
	c.Assert(err, NotNil)
	log.Debugf("failed to remove listener 3: %s", err)
}

func (s *EnvoySuite) TestEnvoyNACK(c *C) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()

	s.waitGroup = completion.NewWaitGroup(ctx)

	if os.Getenv("CILIUM_ENABLE_ENVOY_UNIT_TEST") == "" {
		c.Skip("skipping envoy unit test; CILIUM_ENABLE_ENVOY_UNIT_TEST not set")
	}

	flowdebug.Enable()

	testRunDir, err := os.MkdirTemp("", "envoy_go_test")
	c.Assert(err, IsNil)

	log.Debugf("run directory: %s", testRunDir)

	xdsServer := StartXDSServer(testipcache.NewMockIPCache(), testRunDir)
	defer xdsServer.stop()
	StartAccessLogServer(testRunDir, xdsServer)

	// launch debug variant of the Envoy proxy
	envoyProxy := StartEmbeddedEnvoy(testRunDir, filepath.Join(testRunDir, "cilium-envoy.log"), 42)
	c.Assert(envoyProxy, NotNil)
	log.Debug("started Envoy")

	rName := "listener:22"

	log.Debug("adding ", rName)
	xdsServer.AddListener(rName, policy.ParserTypeHTTP, 22, true, false, s.waitGroup)

	err = s.waitForProxyCompletion()
	c.Assert(err, Not(IsNil))
	c.Assert(err, checker.DeepEquals, &xds.ProxyError{Err: xds.ErrNackReceived, Detail: "Error adding/updating listener(s) listener:22: cannot bind '[::]:22': Address already in use\n"})

	s.waitGroup = completion.NewWaitGroup(ctx)
	// Remove listener1
	log.Debug("removing ", rName)
	xdsServer.RemoveListener(rName, s.waitGroup)
	err = s.waitForProxyCompletion()
	c.Assert(err, IsNil)
}
