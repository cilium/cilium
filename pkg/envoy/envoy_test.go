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

	log.Debug("adding listener1")
	Envoy.AddListener("listener1", "1.2.3.4", 8081, true, &testRedirect{name: "listener1"}, s.waitGroup)

	log.Debug("adding listener2")
	Envoy.AddListener("listener2", "1.2.3.4", 8082, true, &testRedirect{name: "listener2"}, s.waitGroup)

	log.Debug("adding listener3")
	Envoy.AddListener("listener3", "1.2.3.4", 8083, false, &testRedirect{name: "listener3"}, s.waitGroup)

	err := s.waitForProxyCompletion()
	c.Assert(err, IsNil)
	log.Debug("completed adding listener1, listener2, listener3")
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
	Envoy.AddListener("listener3", "1.2.3.4", 8083, false, &testRedirect{name: "listener3"}, s.waitGroup)

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
