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

package npds

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/envoy/cilium"
	envoy_api_v2 "github.com/cilium/cilium/pkg/envoy/envoy/api/v2"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/proxylib/test"

	log "github.com/sirupsen/logrus"
	"gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	logging.ToggleDebugLogs(true)
	check.TestingT(t)
}

type ClientSuite struct{}

var _ = check.Suite(&ClientSuite{})

const (
	TestTimeout      = 10 * time.Second
	CacheUpdateDelay = 250 * time.Millisecond
)

var resources = []*cilium.NetworkPolicy{
	{Name: "resource0"},
	{Name: "resource1"},
	{Name: "resource2"},
}

func ackCallback(err error) {
	if err == nil {
		log.Info("ACK Callback called")
	} else {
		log.Info("NACK Callback called")
	}
}

// UpsertNetworkPolicy must only be used for testing!
func UpsertNetworkPolicy(s *envoy.XDSServer, p *cilium.NetworkPolicy) {
	c := completion.NewCompletion(nil, ackCallback)
	s.NetworkPolicyMutator.Upsert(envoy.NetworkPolicyTypeURL, p.Name, p, []string{"127.0.0.1"}, c)
}

type updater struct{}

func (u *updater) PolicyUpdate(resp *envoy_api_v2.DiscoveryResponse) error {
	log.Infof("Received policy update: %v", *resp)
	return nil
}

func (s *ClientSuite) TestRequestAllResources(c *check.C) {
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
	xdsServer := envoy.StartXDSServer(test.Tmpdir)
	time.Sleep(500 * time.Millisecond)

	// Create version 1 with resource 0.
	UpsertNetworkPolicy(xdsServer, resources[0])

	time.Sleep(DialDelay * BackOffLimit)
}
