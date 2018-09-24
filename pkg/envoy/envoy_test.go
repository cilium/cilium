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

package envoy

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/identity"
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
	if err != nil {
		return errors.New("proxy state changes failed")
	}
	log.Debug("Wait time for proxy updates: ", time.Since(start))
	return nil
}

type dummyEndpointInfoRegistry struct{}

func (r *dummyEndpointInfoRegistry) FillEndpointIdentityByID(id identity.NumericIdentity, info *accesslog.EndpointInfo) bool {
	return false
}

func (r *dummyEndpointInfoRegistry) FillEndpointIdentityByIP(ip net.IP, info *accesslog.EndpointInfo) bool {
	return false
}

func (s *EnvoySuite) TestEnvoy(c *C) {
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

	callback := func(err error) error {
		if err == nil {
			log.Debug("Envoy Acked redirect port")
		}
		return err // Any error causes the wait group to be canceled
	}

	log.Debug("adding listener1")
	xdsServer.AddListener("listener1", policy.ParserTypeHTTP, "1.2.3.4", 8081, true, s.waitGroup.AddCompletionWithCallback(callback))

	log.Debug("adding listener2")
	xdsServer.AddListener("listener2", policy.ParserTypeHTTP, "1.2.3.4", 8082, true, s.waitGroup.AddCompletionWithCallback(callback))

	log.Debug("adding listener3")
	xdsServer.AddListener("listener3", policy.ParserTypeHTTP, "1.2.3.4", 8083, false, s.waitGroup.AddCompletionWithCallback(callback))

	err = s.waitForProxyCompletion()
	c.Assert(err, IsNil)
	log.Debug("completed adding listener1, listener2, listener3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	// Remove listener3
	log.Debug("removing listener 3")
	xdsServer.RemoveListener("listener3", s.waitGroup.AddCompletion())

	err = s.waitForProxyCompletion()
	c.Assert(err, IsNil)
	log.Debug("completed removing listener 3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	// Add listener3 again
	log.Debug("adding listener 3")
	xdsServer.AddListener("listener3", policy.L7ParserType("test.headerparser"), "1.2.3.4", 8083, false, s.waitGroup.AddCompletionWithCallback(callback))

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
	xdsServer.RemoveListener("listener3", s.waitGroup.AddCompletion())
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

	acked := func(port uint16) { log.Debug("Envoy Acked redirect port: ", port) }

	retries := 0
	maxRetries := 10
	baseName := "listener"
	rName := "listener:80"
	ProxyPort := uint16(80)
	pPort := &ProxyPort

	var comp *completion.Completion
	var callback func(err error) error

	callback = func(err error) error {
		switch err {
		case nil:
			acked(*pPort)
		case context.Canceled, context.DeadlineExceeded:
			// nothing
		default:
			// NACK has been received
			oldPort := *pPort
			port := oldPort + 200

			retries++

			// Upsert cannot be called from the callback due to a locks being held.
			go func() {
				// RemoveListener
				xdsServer.RemoveListener(rName, nil) // Not using comp, it will time out.

				// Create a new one with the reallocated port
				if retries < maxRetries {
					*pPort = port
					rName = fmt.Sprintf("%s:%d", baseName, port)
					log.Debugf("Retrying redirect %s with reallocated proxyport (%d -> %d)", rName, oldPort, port)
					xdsServer.AddListener(rName, policy.ParserTypeHTTP, "1.2.3.4", port, true, comp)
					log.Debug("Envoy: Listener updated after NACK")
				}
			}()

			if retries >= maxRetries {
				log.Errorf("Envoy: Failed to apply new listener configuration after %d retries (irrecoverable NACK received), removing listener %s", retries, rName)
				return err
			}
		}
		return nil
	}

	comp = s.waitGroup.AddCompletionWithCallback(callback)

	log.Debug("adding ", rName)
	xdsServer.AddListener(rName, policy.ParserTypeHTTP, "1.2.3.4", ProxyPort, true, comp)

	err = s.waitForProxyCompletion()
	c.Assert(err, IsNil)

	log.Debug("completed adding ", rName)
	s.waitGroup = completion.NewWaitGroup(ctx)

	// Remove listener1
	log.Debug("removing ", rName)
	xdsServer.RemoveListener(rName, s.waitGroup.AddCompletion())
	err = s.waitForProxyCompletion()
	c.Assert(err, IsNil)
}
