// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package npds

import (
	"context"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_service_discovery "github.com/cilium/proxy/go/envoy/service/discovery/v3"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	"github.com/cilium/cilium/proxylib/test"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type ClientSuite struct {
	acks  uint64
	nacks uint64
}

var _ = Suite(&ClientSuite{})

const (
	TestTimeout      = 10 * time.Second
	CacheUpdateDelay = 250 * time.Millisecond
)

var resources = []*cilium.NetworkPolicy{
	{EndpointIps: []string{"1.1.1.1"}},
	{EndpointIps: []string{"2.2.2.2"}},
	{EndpointIps: []string{"3.3.3.3", "face::1"}},
}

// UpsertNetworkPolicy must only be used for testing!
func (cs *ClientSuite) UpsertNetworkPolicy(c *C, s *envoy.XDSServer, p *cilium.NetworkPolicy) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wg := completion.NewWaitGroup(ctx)

	callback := func(err error) {
		if err == nil {
			logrus.Debug("ACK Callback called")
			atomic.AddUint64(&cs.acks, 1)
		} else {
			logrus.Debug("NACK Callback called")
			atomic.AddUint64(&cs.nacks, 1)
		}
	}
	resourceName := strconv.FormatUint(p.EndpointId, 10)
	s.NetworkPolicyMutator.Upsert(envoy.NetworkPolicyTypeURL, resourceName, p, []string{"127.0.0.1"}, wg, callback)
}

type updater struct{}

func (u *updater) PolicyUpdate(resp *envoy_service_discovery.DiscoveryResponse) error {
	logrus.Debugf("Received policy update: %s", resp.String())
	return nil
}

func (s *ClientSuite) TestRequestAllResources(c *C) {
	var updater *updater
	xdsPath := filepath.Join(test.Tmpdir, "xds.sock")
	client1 := NewClient(xdsPath, "sidecar~127.0.0.1~v0.default~default.svc.cluster.local", updater)
	if client1 == nil {
		c.Error("NewClient() failed")
	}

	// Start another client, which will never connect
	xdsPath2 := filepath.Join(test.Tmpdir, "xds.sock2")
	client2 := NewClient(xdsPath2, "sidecar~127.0.0.2~v0.default~default.svc.cluster.local", updater)
	if client2 == nil {
		c.Error("NewClient() failed")
	}

	// Some wait before server is made available
	time.Sleep(500 * time.Millisecond)
	xdsServer := envoy.StartXDSServer(testipcache.NewMockIPCache(), test.Tmpdir)
	time.Sleep(500 * time.Millisecond)

	// Create version 1 with resource 0.
	s.UpsertNetworkPolicy(c, xdsServer, resources[0])

	time.Sleep(DialDelay * BackOffLimit)
	c.Assert(atomic.LoadUint64(&s.acks), Equals, uint64(1))
	c.Assert(atomic.LoadUint64(&s.nacks), Equals, uint64(0))
}
