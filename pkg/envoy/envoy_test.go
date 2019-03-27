// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package envoy

import (
	"context"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"

	"github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
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

type dummyEndpointInfoRegistry struct{}

func (r *dummyEndpointInfoRegistry) FillEndpointIdentityByID(id identity.NumericIdentity, info *accesslog.EndpointInfo) bool {
	return false
}

func (r *dummyEndpointInfoRegistry) FillEndpointIdentityByIP(ip net.IP, info *accesslog.EndpointInfo) bool {
	return false
}

func (s *EnvoySuite) TestEnvoy(c *C) {
	option.Config.Populate()
	option.Config.ProxyConnectTimeout = 1
	c.Assert(option.Config.ProxyConnectTimeout, Not(Equals), 0)
	log.Logger.SetLevel(logrus.DebugLevel)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s.waitGroup = completion.NewWaitGroup(ctx)

	if os.Getenv("CILIUM_ENABLE_ENVOY_UNIT_TEST") == "" {
		c.Skip("skipping envoy unit test; CILIUM_ENABLE_ENVOY_UNIT_TEST not set")
	}

	flowdebug.Enable()

	stateLogDir, err := ioutil.TempDir("", "envoy_go_test")
	c.Assert(err, IsNil)

	log.Debugf("state log directory: %s", stateLogDir)

	xdsServer := StartXDSServer(stateLogDir)
	defer xdsServer.stop()
	StartAccessLogServer(stateLogDir, xdsServer, &dummyEndpointInfoRegistry{})

	// launch debug variant of the Envoy proxy
	envoyProxy := StartEnvoy(stateLogDir, filepath.Join(stateLogDir, "cilium-envoy.log"), 42)
	c.Assert(envoyProxy, NotNil)
	log.Debug("started Envoy")

	log.Debug("adding listener1")
	xdsServer.AddListener("listener1", policy.ParserTypeHTTP, 8081, true, s.waitGroup)

	log.Debug("adding listener2")
	xdsServer.AddListener("listener2", policy.ParserTypeHTTP, 8082, true, s.waitGroup)

	log.Debug("adding listener3")
	xdsServer.AddListener("listener3", policy.ParserTypeHTTP, 8083, false, s.waitGroup)

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
	xdsServer.AddListener("listener3", policy.L7ParserType("test.headerparser"), 8083, false, s.waitGroup)

	err = s.waitForProxyCompletion()
	c.Assert(err, IsNil)
	log.Debug("completed adding listener 3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	log.Debug("stopping Envoy")
	err = envoyProxy.StopEnvoy()
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
	log.Logger.SetLevel(logrus.DebugLevel)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()

	s.waitGroup = completion.NewWaitGroup(ctx)

	if os.Getenv("CILIUM_ENABLE_ENVOY_UNIT_TEST") == "" {
		c.Skip("skipping envoy unit test; CILIUM_ENABLE_ENVOY_UNIT_TEST not set")
	}

	flowdebug.Enable()

	stateLogDir, err := ioutil.TempDir("", "envoy_go_test")
	c.Assert(err, IsNil)

	log.Debugf("state log directory: %s", stateLogDir)

	xdsServer := StartXDSServer(stateLogDir)
	defer xdsServer.stop()
	StartAccessLogServer(stateLogDir, xdsServer, &dummyEndpointInfoRegistry{})

	// launch debug variant of the Envoy proxy
	envoyProxy := StartEnvoy(stateLogDir, filepath.Join(stateLogDir, "cilium-envoy.log"), 42)
	c.Assert(envoyProxy, NotNil)
	log.Debug("started Envoy")

	rName := "listener:22"

	log.Debug("adding ", rName)
	xdsServer.AddListener(rName, policy.ParserTypeHTTP, 22, true, s.waitGroup)

	err = s.waitForProxyCompletion()
	c.Assert(err, Not(IsNil))
	c.Assert(err, checker.DeepEquals, &xds.ProxyError{Err: xds.ErrNackReceived, Detail: "Error adding/updating listener listener:22: cannot bind '[::]:22': Address already in use"})

	s.waitGroup = completion.NewWaitGroup(ctx)
	// Remove listener1
	log.Debug("removing ", rName)
	xdsServer.RemoveListener(rName, s.waitGroup)
	err = s.waitForProxyCompletion()
	c.Assert(err, IsNil)
}
