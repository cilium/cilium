// Copyright 2019 Authors of Cilium
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

package endpoint

import (
	"context"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	fakeConfig "github.com/cilium/cilium/pkg/option/fake"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/u8proto"
	"gopkg.in/check.v1"
)

type RedirectSuite struct{}

// suite can be used by testing.T benchmarks or tests as a mock regeneration.Owner
var redirectSuite = RedirectSuite{}
var _ = check.Suite(&redirectSuite)

// RedirectSuiteProxy implements EndpointProxy. It is used for testing the
// functions related to generating proxy redirects for a given Endpoint.
type RedirectSuiteProxy struct {
	parserProxyPortMap  map[policy.L7ParserType]uint16
	redirectPortUserMap map[uint16][]string
}

// CreateOrUpdateRedirect returns the proxy port for the given L7Parser from the
// ProxyPolicy parameter.
func (r *RedirectSuiteProxy) CreateOrUpdateRedirect(ctx context.Context, l4 policy.ProxyPolicy, id string, localEndpoint logger.EndpointUpdater, wg *completion.WaitGroup) (proxyPort uint16, err error, finalizeFunc revert.FinalizeFunc, revertFunc revert.RevertFunc) {
	pp := r.parserProxyPortMap[l4.GetL7Parser()]
	return pp, nil, nil, nil
}

// RemoveRedirect does nothing.
func (r *RedirectSuiteProxy) RemoveRedirect(id string, wg *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	return nil, nil, nil
}

// UpdateNetworkPolicy does nothing.
func (r *RedirectSuiteProxy) UpdateNetworkPolicy(ep logger.EndpointUpdater, policy *policy.L4Policy, ingressPolicyEnforced, egressPolicyEnforced bool, wg *completion.WaitGroup) (error, func() error) {
	return nil, nil
}

// UseCurrentNetworkPolicy does nothing.
func (r *RedirectSuiteProxy) UseCurrentNetworkPolicy(ep logger.EndpointUpdater, policy *policy.L4Policy, wg *completion.WaitGroup) {
}

// RemoveNetworkPolicy does nothing.
func (r *RedirectSuiteProxy) RemoveNetworkPolicy(ep logger.EndpointInfoSource) {}

// DummyIdentityAllocatorOwner implements
// pkg/identity/cache/IdentityAllocatorOwner. It is used for unit testing.
type DummyIdentityAllocatorOwner struct{}

// UpdateIdentities does nothing.
func (d *DummyIdentityAllocatorOwner) UpdateIdentities(added, deleted cache.IdentityCache) {
	return
}

// GetNodeSuffix does nothing.
func (d *DummyIdentityAllocatorOwner) GetNodeSuffix() string {
	return ""
}

// DummyOwner implements pkg/endpoint/regeneration/Owner. Used for unit testing.
type DummyOwner struct {
	repo *policy.Repository
}

// GetPolicyRepository returns the policy repository of the owner.
func (d *DummyOwner) GetPolicyRepository() *policy.Repository {
	return d.repo
}

// QueueEndpointBuild does nothing.
func (d *DummyOwner) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	return nil, nil
}

// GetCompilationLock does nothing.
func (d *DummyOwner) GetCompilationLock() *lock.RWMutex {
	return nil
}

// GetCIDRPrefixLengths does nothing.
func (d *DummyOwner) GetCIDRPrefixLengths() (s6, s4 []int) {
	return nil, nil
}

// SendNotification does nothing.
func (d *DummyOwner) SendNotification(msg monitorAPI.AgentNotifyMessage) error {
	return nil
}

// Datapath returns a nil datapath.
func (d *DummyOwner) Datapath() datapath.Datapath {
	return nil
}

func (s *DummyOwner) GetDNSRules(epID uint16) restore.DNSRules {
	return nil
}

func (s *DummyOwner) RemoveRestoredDNSRules(epID uint16) {
}

// GetNodeSuffix does nothing.
func (d *DummyOwner) GetNodeSuffix() string {
	return ""
}

// UpdateIdentities does nothing.
func (d *DummyOwner) UpdateIdentities(added, deleted cache.IdentityCache) {}

func (s *RedirectSuite) TestAddVisibilityRedirects(c *check.C) {
	// Setup dependencies for endpoint.
	kvstore.SetupDummy("etcd")
	defer kvstore.Client().Close()

	identity.InitWellKnownIdentities(&fakeConfig.Config{})
	idAllocatorOwner := &DummyIdentityAllocatorOwner{}

	mgr := NewCachingIdentityAllocator(idAllocatorOwner)
	<-mgr.InitIdentityAllocator(nil, nil)
	defer mgr.Close()

	do := &DummyOwner{
		repo: policy.NewPolicyRepository(nil, nil, nil),
	}
	identitymanager.Subscribe(do.repo)

	lblQA := labels.ParseLabel("QA")
	lblBar := labels.ParseLabel("bar")

	httpPort := uint16(19001)
	dnsPort := uint16(19002)
	kafkaPort := uint16(19003)

	rsp := &RedirectSuiteProxy{
		parserProxyPortMap: map[policy.L7ParserType]uint16{
			policy.ParserTypeHTTP:  httpPort,
			policy.ParserTypeDNS:   dnsPort,
			policy.ParserTypeKafka: kafkaPort,
		},
		redirectPortUserMap: make(map[uint16][]string),
	}

	ep := NewEndpointWithState(do, rsp, mgr, 12345, StateRegenerating)

	qaBarLbls := labels.Labels{lblBar.Key: lblBar, lblQA.Key: lblQA}
	epIdentity, _, err := mgr.AllocateIdentity(context.Background(), qaBarLbls, true, identity.InvalidIdentity)
	c.Assert(err, check.IsNil)
	ep.SetIdentity(epIdentity, true)

	firstAnno := "<Ingress/80/TCP/HTTP>"
	ep.UpdateVisibilityPolicy(func(_, _ string) (proxyVisibility string, err error) {
		return firstAnno, nil
	})
	err = ep.regeneratePolicy()
	c.Assert(err, check.IsNil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmp := completion.NewWaitGroup(ctx)

	_, err, _, _ = ep.addNewRedirects(cmp)
	c.Assert(err, check.IsNil)
	v, ok := ep.desiredPolicy.PolicyMapState[policy.Key{
		Identity:         0,
		DestPort:         uint16(80),
		Nexthdr:          uint8(u8proto.TCP),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	}]
	c.Assert(ok, check.Equals, true)
	c.Assert(v.ProxyPort, check.Equals, httpPort)

	secondAnno := "<Ingress/80/TCP/Kafka>"

	ep.UpdateVisibilityPolicy(func(_, _ string) (proxyVisibility string, err error) {
		return secondAnno, nil
	})
	d, err, _, _ := ep.addNewRedirects(cmp)
	c.Assert(err, check.IsNil)
	v, ok = ep.desiredPolicy.PolicyMapState[policy.Key{
		Identity:         0,
		DestPort:         uint16(80),
		Nexthdr:          uint8(u8proto.TCP),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	}]
	c.Assert(ok, check.Equals, true)
	// Check that proxyport was updated accordingly.
	c.Assert(v.ProxyPort, check.Equals, kafkaPort)

	thirdAnno := "<Ingress/80/TCP/Kafka>,<Egress/80/TCP/HTTP>"

	// Check that multiple values in annotation are handled correctly.
	ep.UpdateVisibilityPolicy(func(_, _ string) (proxyVisibility string, err error) {
		return thirdAnno, nil
	})
	_, err, _, _ = ep.addNewRedirects(cmp)
	c.Assert(err, check.IsNil)
	v, ok = ep.desiredPolicy.PolicyMapState[policy.Key{
		Identity:         0,
		DestPort:         uint16(80),
		Nexthdr:          uint8(u8proto.TCP),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	}]
	c.Assert(ok, check.Equals, true)
	c.Assert(v.ProxyPort, check.Equals, kafkaPort)

	v, ok = ep.desiredPolicy.PolicyMapState[policy.Key{
		Identity:         0,
		DestPort:         uint16(80),
		Nexthdr:          uint8(u8proto.TCP),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	}]
	c.Assert(ok, check.Equals, true)
	c.Assert(v.ProxyPort, check.Equals, kafkaPort)

	v, ok = ep.desiredPolicy.PolicyMapState[policy.Key{
		Identity:         0,
		DestPort:         uint16(80),
		Nexthdr:          uint8(u8proto.TCP),
		TrafficDirection: trafficdirection.Egress.Uint8(),
	}]
	c.Assert(ok, check.Equals, true)
	c.Assert(v.ProxyPort, check.Equals, httpPort)
	pID := policy.ProxyID(ep.ID, false, u8proto.TCP.String(), uint16(80))
	p, ok := ep.realizedRedirects[pID]
	c.Assert(ok, check.Equals, true)
	c.Assert(p, check.Equals, httpPort)

	// Check that the egress redirect is removed when the redirects have been
	// updated.
	ep.removeOldRedirects(d, cmp)
	// Egress redirect should be removed.
	_, ok = ep.realizedRedirects[pID]
	c.Assert(ok, check.Equals, false)

	// Check that all redirects are removed when no visibility policy applies.
	noAnno := ""
	ep.UpdateVisibilityPolicy(func(_, _ string) (proxyVisibility string, err error) {
		return noAnno, nil
	})
	d, err, _, _ = ep.addNewRedirects(cmp)
	c.Assert(err, check.IsNil)
	ep.removeOldRedirects(d, cmp)
	c.Assert(len(ep.realizedRedirects), check.Equals, 0)
}
