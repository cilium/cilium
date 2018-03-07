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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/sirupsen/logrus"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type EnvoySuite struct {
	waitGroup *completion.WaitGroup
}

var _ = Suite(&EnvoySuite{})

type testRedirect struct {
	name string
}

func (t *testRedirect) Log(pblog *HttpLogEntry) {
	log.Infof("%s/%s: Access log message: %s", t.name, pblog.CiliumResourceName, pblog.String())
}

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

func (s *EnvoySuite) TestEnvoy(c *C) {
	log.SetLevel(logrus.DebugLevel)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s.waitGroup = completion.NewWaitGroup(ctx)

	if os.Getenv("CILIUM_ENABLE_ENVOY_UNIT_TEST") == "" {
		c.Skip("skipping envoy unit test; CILIUM_ENABLE_ENVOY_UNIT_TEST not set")
	}

	stateLogDir := c.MkDir()
	log.Debugf("state log directory: %s", stateLogDir)

	// launch debug variant of the Envoy proxy
	Envoy := StartEnvoy(9942, stateLogDir, filepath.Join(stateLogDir, "cilium-envoy.log"), 42)
	c.Assert(Envoy, NotNil)
	log.Debug("started Envoy")

	sel := api.NewWildcardEndpointSelector()

	// TODO: Test for success once we get feedback from Envoy.
	log.Debug("adding listener1")
	Envoy.AddListener("listener1", 8081, policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Path: "foo"},
			{Method: "POST"},
			{Host: "cilium"},
			{Headers: []string{"via"}}}}},
		true, &testRedirect{name: "listener1"}, s.waitGroup)

	log.Debug("adding listener2")
	Envoy.AddListener("listener2", 8082, policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Headers: []string{"via", "x-foo: bar"}}}}},
		true, &testRedirect{name: "listener2"}, s.waitGroup)

	log.Debug("adding listener3")
	Envoy.AddListener("listener3", 8083, policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Method: "GET", Path: ".*public"}}}},
		false, &testRedirect{name: "listener3"}, s.waitGroup)

	err := s.waitForProxyCompletion()
	c.Assert(err, IsNil)
	log.Debug("completed adding listener1, listener2, listener3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	// Update listener2
	log.Debug("updating listener 2")
	Envoy.UpdateListener("listener2", policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Headers: []string{"via: home", "x-foo: bar"}}}}}, s.waitGroup)

	err = s.waitForProxyCompletion()
	c.Assert(err, IsNil)
	log.Debug("completed updating listener 2")
	s.waitGroup = completion.NewWaitGroup(ctx)

	// Update listener1
	log.Debug("updating listener 1")
	Envoy.UpdateListener("listener1", policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Headers: []string{"via"}}}}}, s.waitGroup)

	err = s.waitForProxyCompletion()
	c.Assert(err, IsNil)
	log.Debug("completed updating listener 1")
	s.waitGroup = completion.NewWaitGroup(ctx)

	// Remove listener3
	log.Debug("removing listener 3")
	Envoy.RemoveListener("listener3", s.waitGroup)

	err = s.waitForProxyCompletion()
	c.Assert(err, IsNil)
	log.Debug("completed removing listener 3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	// Add listener3 again
	log.Debug("adding listener 3")
	Envoy.AddListener("listener3", 8083, policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Method: "GET", Path: ".*public"}}}},
		false, &testRedirect{name: "listener3"}, s.waitGroup)

	err = s.waitForProxyCompletion()
	c.Assert(err, IsNil)
	log.Debug("completed adding listener 3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	// Remove listener3 again, and wait for timeout after stopping Envoy.
	log.Debug("removing listener 3")
	Envoy.RemoveListener("listener3", s.waitGroup)
	err = Envoy.StopEnvoy()
	c.Assert(err, IsNil)
	err = s.waitForProxyCompletion()
	c.Assert(err, NotNil)
	log.Debugf("failed to remove listener 3: %s", err)
}
