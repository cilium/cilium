package envoy

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/sirupsen/logrus"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type completions struct {
	c      *C
	wg     sync.WaitGroup
	lock   lock.Mutex
	errors int
	done   bool
}

type EnvoySuite struct {
	completions *completions
}

var _ = Suite(&EnvoySuite{})

type testRedirect struct {
	name string
}

func (t *testRedirect) Log(pblog *HttpLogEntry) {
	log.Infof("%s/%s: Access log message: %s", t.name, pblog.CiliumResourceName, pblog.String())
}

// May be called from any goroutine without holding any locks
func (c *completions) Completed(success bool) {
	log.Debug("completions.Completed: ", success)
	// Debugging, not locked, etc.
	c.c.Assert(c.done, Equals, false)
	if !success {
		c.lock.Lock()
		c.errors++
		c.lock.Unlock()
	}
	c.wg.Done()
}

func (s *EnvoySuite) AddCompletion() (policy.Completion, time.Duration) {
	s.completions.wg.Add(1)
	return s.completions, time.Duration(10) * time.Second
}

func (s *EnvoySuite) waitForProxyCompletion() error {
	start := time.Now()
	log.Debug("Waiting for proxy updates to complete...")
	s.completions.wg.Wait()
	// Wait is done, no parallel access any more
	s.completions.done = true
	if s.completions.errors > 0 {
		return fmt.Errorf("%d proxy state changes failed", s.completions.errors)
	}
	log.Debug("Proxy updates completed in ", time.Since(start))
	return nil
}

func (s *EnvoySuite) TestEnvoy(c *C) {
	log.SetLevel(logrus.DebugLevel)

	s.completions = &completions{c: c}

	if os.Getenv("CILIUM_ENABLE_ENVOY_UNIT_TEST") == "" {
		c.Skip("skipping envoy unit test; CILIUM_ENABLE_ENVOY_UNIT_TEST not set")
	}

	stateLogDir := c.MkDir()

	// launch debug variant of the Envoy proxy
	Envoy := StartEnvoy(9942, stateLogDir, stateLogDir, 42)
	c.Assert(Envoy, NotNil)

	sel := api.NewWildcardEndpointSelector()

	// TODO: Test for success once we get feedback from Envoy.
	Envoy.AddListener("listener1", 8081, policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Path: "foo"},
			{Method: "POST"},
			{Host: "cilium"},
			{Headers: []string{"via"}}}}},
		true, &testRedirect{name: "listener1"}, s)
	Envoy.AddListener("listener2", 8082, policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Headers: []string{"via", "x-foo: bar"}}}}},
		true, &testRedirect{name: "listener2"}, s)
	Envoy.AddListener("listener3", 8083, policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Method: "GET", Path: ".*public"}}}},
		false, &testRedirect{name: "listener3"}, s)

	err := s.waitForProxyCompletion()
	c.Assert(err, IsNil)
	s.completions = &completions{c: c}

	// Update listener2
	Envoy.UpdateListener("listener2", policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Headers: []string{"via: home", "x-foo: bar"}}}}}, s)

	err = s.waitForProxyCompletion()
	c.Assert(err, IsNil)
	s.completions = &completions{c: c}

	// Update listener1
	Envoy.UpdateListener("listener1", policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Headers: []string{"via"}}}}}, s)

	err = s.waitForProxyCompletion()
	c.Assert(err, IsNil)
	s.completions = &completions{c: c}

	// Remove listener3
	Envoy.RemoveListener("listener3", s)

	err = s.waitForProxyCompletion()
	c.Assert(err, IsNil)
	s.completions = &completions{c: c}

	// Add listener3 again
	Envoy.AddListener("listener3", 8083, policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Method: "GET", Path: ".*public"}}}},
		false, &testRedirect{name: "listener3"}, s)

	err = s.waitForProxyCompletion()
	c.Assert(err, IsNil)
	s.completions = &completions{c: c}

	// Remove listener3 again, but do not wait for completion
	Envoy.RemoveListener("listener3", s)
	err = Envoy.StopEnvoy()
	c.Assert(err, IsNil)
	err = s.waitForProxyCompletion()
	c.Assert(err, NotNil)
	c.Assert(s.completions.errors, Equals, 1)
	log.Debug("Proxy updates failed: ", err)

	time.Sleep(10 * time.Millisecond)
}
