package envoy

import (
	"os"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/sirupsen/logrus"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type EnvoySuite struct{}

var _ = Suite(&EnvoySuite{})

type testRedirect struct {
	name string
}

func (t *testRedirect) Log(pblog *HttpLogEntry) {
	log.Infof("%s/%s: Access log message: %s", t.name, pblog.CiliumResourceName, pblog.String())
}

func (s *EnvoySuite) TestEnvoy(c *C) {
	log.SetLevel(logrus.DebugLevel)

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
		true, &testRedirect{name: "listener1"})
	Envoy.AddListener("listener2", 8082, policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Headers: []string{"via", "x-foo: bar"}}}}},
		true, &testRedirect{name: "listener2"})
	Envoy.AddListener("listener3", 8083, policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Method: "GET", Path: ".*public"}}}},
		false, &testRedirect{name: "listener3"})

	time.Sleep(100 * time.Millisecond)

	// Update listener2
	Envoy.UpdateListener("listener2", policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Headers: []string{"via: home", "x-foo: bar"}}}}})

	time.Sleep(100 * time.Millisecond)

	// Update listener1
	Envoy.UpdateListener("listener1", policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Headers: []string{"via"}}}}})

	time.Sleep(100 * time.Millisecond)

	// Remove listener3
	Envoy.RemoveListener("listener3")

	time.Sleep(100 * time.Millisecond)

	// Add listener3 again
	Envoy.AddListener("listener3", 8083, policy.L7DataMap{
		sel: api.L7Rules{HTTP: []api.PortRuleHTTP{
			{Method: "GET", Path: ".*public"}}}},
		false, &testRedirect{name: "listener3"})

	time.Sleep(100 * time.Millisecond)

	// Remove listener3 again
	Envoy.RemoveListener("listener3")

	time.Sleep(100 * time.Millisecond)

	err := Envoy.StopEnvoy()
	c.Assert(err, IsNil)

	time.Sleep(10 * time.Millisecond)
}
