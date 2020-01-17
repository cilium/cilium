// Copyright 2016-2019 Authors of Cilium
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

package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/testutils"

	"github.com/cilium/proxy/go/cilium/api"
	envoy_api_v2_core "github.com/cilium/proxy/go/envoy/api/v2/core"
	envoy_api_v2_route "github.com/cilium/proxy/go/envoy/api/v2/route"
	. "gopkg.in/check.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

var (
	QAIPv6Addr, _   = addressing.NewCiliumIPv6("beef:beef:beef:beef:aaaa:aaaa:1111:1112")
	QAIPv4Addr, _   = addressing.NewCiliumIPv4("10.11.12.13")
	ProdIPv6Addr, _ = addressing.NewCiliumIPv6("cafe:cafe:cafe:cafe:aaaa:aaaa:1111:1112")
	ProdIPv4Addr, _ = addressing.NewCiliumIPv4("10.11.12.14")

	lblProd = labels.ParseLabel("Prod")
	lblQA   = labels.ParseLabel("QA")
	lblFoo  = labels.ParseLabel("foo")
	lblBar  = labels.ParseLabel("bar")
	lblJoe  = labels.ParseLabel("user=joe")
	lblPete = labels.ParseLabel("user=pete")

	testEndpointID = uint16(1)

	regenerationMetadata = &regeneration.ExternalRegenerationMetadata{
		Reason: "test",
	}

	CNPAllowTCP80 = api.PortRule{
		Ports: []api.PortProtocol{
			{Port: "80", Protocol: api.ProtoTCP},
		},
	}
	CNPAllowGETbar = api.PortRule{
		Ports: CNPAllowTCP80.Ports,
		Rules: &api.L7Rules{
			HTTP: []api.PortRuleHTTP{
				{
					Path:   "/bar",
					Method: "GET",
				},
			},
		},
	}

	PNPAllowAll = cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				{},
			},
		},
	}
	PNPAllowGETbar = cilium.PortNetworkPolicyRule_HttpRules{
		HttpRules: &cilium.HttpNetworkPolicyRules{
			HttpRules: []*cilium.HttpNetworkPolicyRule{
				{
					Headers: []*envoy_api_v2_route.HeaderMatcher{
						{
							Name:                 ":method",
							HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_RegexMatch{RegexMatch: "GET"},
						},
						{
							Name:                 ":path",
							HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_RegexMatch{RegexMatch: "/bar"},
						},
					},
				},
			},
		},
	}
)

// getXDSNetworkPolicies returns the representation of the xDS network policies
// as a map of IP addresses to NetworkPolicy objects
func (ds *DaemonSuite) getXDSNetworkPolicies(c *C, resourceNames []string) map[string]*cilium.NetworkPolicy {
	networkPolicies, err := ds.d.l7Proxy.GetNetworkPolicies(resourceNames)
	c.Assert(err, IsNil)
	return networkPolicies
}

func prepareEndpointDirs() (cleanup func(), err error) {
	testEPDir := fmt.Sprintf("%d", testEndpointID)
	if err = os.Mkdir(testEPDir, 755); err != nil {
		return func() {}, err
	}
	return func() {
		os.RemoveAll(fmt.Sprintf("%s/lxc_config.h", testEPDir))
		time.Sleep(1 * time.Second)
		os.RemoveAll(testEPDir)
		os.RemoveAll(fmt.Sprintf("%s_backup", testEPDir))
	}, nil
}

func (ds *DaemonSuite) prepareEndpoint(c *C, identity *identity.Identity, qa bool) *endpoint.Endpoint {
	e := endpoint.NewEndpointWithState(ds.d, ds.d.l7Proxy, ds.d.identityAllocator, testEndpointID, endpoint.StateWaitingForIdentity)
	if qa {
		e.IPv6 = QAIPv6Addr
		e.IPv4 = QAIPv4Addr
	} else {
		e.IPv6 = ProdIPv6Addr
		e.IPv4 = ProdIPv4Addr
	}
	e.SetIdentity(identity, true)

	ready := e.SetState(endpoint.StateWaitingToRegenerate, "test")
	c.Assert(ready, Equals, true)
	buildSuccess := <-e.Regenerate(regenerationMetadata)
	c.Assert(buildSuccess, Equals, true)

	return e
}

func (ds *DaemonSuite) regenerateEndpoint(c *C, e *endpoint.Endpoint) {
	ready := e.SetState(endpoint.StateWaitingToRegenerate, "test")
	c.Assert(ready, Equals, true)
	buildSuccess := <-e.Regenerate(regenerationMetadata)
	c.Assert(buildSuccess, Equals, true)
}

func (ds *DaemonSuite) TestUpdateConsumerMap(c *C) {
	rules := api.Rules{
		{
			EndpointSelector: api.NewESFromLabels(lblBar),
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(lblJoe),
						api.NewESFromLabels(lblPete),
						api.NewESFromLabels(lblFoo),
					},
				},
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(lblFoo),
					},
					ToPorts: []api.PortRule{
						// Allow Port 80 GET /bar
						CNPAllowGETbar,
					},
				},
			},
		},
		{
			EndpointSelector: api.NewESFromLabels(lblQA),
			Ingress: []api.IngressRule{
				{
					FromRequires: []api.EndpointSelector{
						api.NewESFromLabels(lblQA),
					},
				},
			},
		},
		{
			EndpointSelector: api.NewESFromLabels(lblProd),
			Ingress: []api.IngressRule{
				{
					FromRequires: []api.EndpointSelector{
						api.NewESFromLabels(lblProd),
					},
				},
			},
		},
	}

	ds.d.l7Proxy.RemoveAllNetworkPolicies()

	_, err3 := ds.d.PolicyAdd(rules, nil)
	c.Assert(err3, Equals, nil)

	// Prepare the identities necessary for testing
	qaBarLbls := labels.Labels{lblBar.Key: lblBar, lblQA.Key: lblQA}
	qaBarSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), qaBarLbls, true)
	c.Assert(err, Equals, nil)
	defer ds.d.identityAllocator.Release(context.Background(), qaBarSecLblsCtx)
	prodBarLbls := labels.Labels{lblBar.Key: lblBar, lblProd.Key: lblProd}
	prodBarSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), prodBarLbls, true)
	c.Assert(err, Equals, nil)
	defer ds.d.identityAllocator.Release(context.Background(), prodBarSecLblsCtx)
	qaFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblQA.Key: lblQA}
	qaFooSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), qaFooLbls, true)
	c.Assert(err, Equals, nil)
	defer ds.d.identityAllocator.Release(context.Background(), qaFooSecLblsCtx)
	prodFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblProd.Key: lblProd}
	prodFooSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), prodFooLbls, true)
	c.Assert(err, Equals, nil)
	defer ds.d.identityAllocator.Release(context.Background(), prodFooSecLblsCtx)
	prodFooJoeLbls := labels.Labels{lblFoo.Key: lblFoo, lblProd.Key: lblProd, lblJoe.Key: lblJoe}
	prodFooJoeSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), prodFooJoeLbls, true)
	c.Assert(err, Equals, nil)
	defer ds.d.identityAllocator.Release(context.Background(), prodFooJoeSecLblsCtx)

	// Prepare endpoints
	cleanup, err2 := prepareEndpointDirs()
	c.Assert(err2, Equals, nil)
	defer cleanup()

	e := ds.prepareEndpoint(c, qaBarSecLblsCtx, true)
	c.Assert(e.Allows(qaBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(prodBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(qaFooSecLblsCtx.ID), Equals, true)
	c.Assert(e.Allows(prodFooSecLblsCtx.ID), Equals, false)

	e = ds.prepareEndpoint(c, prodBarSecLblsCtx, false)
	c.Assert(e.Allows(0), Equals, false)
	c.Assert(e.Allows(qaBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(prodBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(qaFooSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(prodFooSecLblsCtx.ID), Equals, true)
	c.Assert(e.Allows(prodFooJoeSecLblsCtx.ID), Equals, true)

	// Check that both policies have been updated in the xDS cache for the L7
	// proxies.
	networkPolicies := ds.getXDSNetworkPolicies(c, nil)
	c.Assert(networkPolicies, HasLen, 4)

	qaBarNetworkPolicy := networkPolicies[QAIPv4Addr.String()]
	c.Assert(qaBarNetworkPolicy, Not(IsNil))
	expectedRemotePolicies := []uint64{
		uint64(qaFooSecLblsCtx.ID),
		// The prodFoo* identities are allowed by FromEndpoints but rejected by
		// FromRequires, so they are not included in the remote policies:
		// uint64(prodFooSecLblsCtx.ID),
		// uint64(prodFooJoeSecLblsCtx.ID),
	}
	sort.Slice(expectedRemotePolicies, func(i, j int) bool {
		return expectedRemotePolicies[i] < expectedRemotePolicies[j]
	})
	expectedNetworkPolicy := &cilium.NetworkPolicy{
		Name:             QAIPv4Addr.String(),
		Policy:           uint64(qaBarSecLblsCtx.ID),
		ConntrackMapName: "global",
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: envoy_api_v2_core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: expectedRemotePolicies,
						L7:             &PNPAllowAll,
					},
					//{
					//	RemotePolicies: expectedRemotePolicies,
					//	L7:             &PNPAllowGETbar,
					//},
				},
			},
		},
	}
	c.Assert(qaBarNetworkPolicy, checker.Equals, expectedNetworkPolicy)

	prodBarNetworkPolicy := networkPolicies[ProdIPv4Addr.String()]
	c.Assert(prodBarNetworkPolicy, Not(IsNil))
	expectedRemotePolicies = []uint64{
		// The qaFoo identity is allowed by FromEndpoints but rejected by
		// FromRequires, so it is not included in the remote policies:
		// uint64(qaFooSecLblsCtx.ID),
		uint64(prodFooSecLblsCtx.ID),
		uint64(prodFooJoeSecLblsCtx.ID),
	}
	sort.Slice(expectedRemotePolicies, func(i, j int) bool {
		return expectedRemotePolicies[i] < expectedRemotePolicies[j]
	})
	expectedRemotePolicies2 := []uint64{
		uint64(prodFooJoeSecLblsCtx.ID),
	}
	sort.Slice(expectedRemotePolicies2, func(i, j int) bool {
		return expectedRemotePolicies2[i] < expectedRemotePolicies2[j]
	})

	expectedNetworkPolicy = &cilium.NetworkPolicy{
		Name:             ProdIPv4Addr.String(),
		Policy:           uint64(prodBarSecLblsCtx.ID),
		ConntrackMapName: "global",
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: envoy_api_v2_core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: expectedRemotePolicies2,
						L7:             &PNPAllowAll,
					},
					{
						RemotePolicies: expectedRemotePolicies,
						L7:             &PNPAllowAll,
					},
					//{
					//	RemotePolicies: expectedRemotePolicies,
					//	L7:             &PNPAllowGETbar,
					//},
				},
			},
		},
	}
	c.Assert(prodBarNetworkPolicy, checker.Equals, expectedNetworkPolicy)
}

func (ds *DaemonSuite) TestL4_L7_Shadowing(c *C) {
	// Prepare the identities necessary for testing
	qaBarLbls := labels.Labels{lblBar.Key: lblBar, lblQA.Key: lblQA}
	qaBarSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), qaBarLbls, true)
	c.Assert(err, Equals, nil)
	defer ds.d.identityAllocator.Release(context.Background(), qaBarSecLblsCtx)
	qaFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblQA.Key: lblQA}
	qaFooSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), qaFooLbls, true)
	c.Assert(err, Equals, nil)
	defer ds.d.identityAllocator.Release(context.Background(), qaFooSecLblsCtx)

	rules := api.Rules{
		{
			EndpointSelector: api.NewESFromLabels(lblBar),
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{
						// Allow all on port 80 (no proxy)
						CNPAllowTCP80,
					},
				},
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(lblFoo),
					},
					ToPorts: []api.PortRule{
						// Allow Port 80 GET /bar
						CNPAllowGETbar,
					},
				},
			},
		},
	}

	ds.d.l7Proxy.RemoveAllNetworkPolicies()

	_, err = ds.d.PolicyAdd(rules, nil)
	c.Assert(err, Equals, nil)

	// Prepare endpoints
	cleanup, err := prepareEndpointDirs()
	c.Assert(err, Equals, nil)
	defer cleanup()

	e := ds.prepareEndpoint(c, qaBarSecLblsCtx, true)
	c.Assert(e.Allows(qaBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(qaFooSecLblsCtx.ID), Equals, false)

	// Check that both policies have been updated in the xDS cache for the L7
	// proxies.
	networkPolicies := ds.getXDSNetworkPolicies(c, nil)
	c.Assert(networkPolicies, HasLen, 2)

	qaBarNetworkPolicy := networkPolicies[QAIPv4Addr.String()]
	expectedNetworkPolicy := &cilium.NetworkPolicy{
		Name:             QAIPv4Addr.String(),
		Policy:           uint64(qaBarSecLblsCtx.ID),
		ConntrackMapName: "global",
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: envoy_api_v2_core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: nil,
						L7:             &PNPAllowAll,
					},
					{
						RemotePolicies: []uint64{uint64(qaFooSecLblsCtx.ID)},
						L7:             &PNPAllowGETbar,
					},
				},
			},
		},
	}
	c.Assert(qaBarNetworkPolicy, checker.Equals, expectedNetworkPolicy)
}

func (ds *DaemonSuite) TestReplacePolicy(c *C) {
	lbls := labels.ParseLabelArray("foo", "bar")
	rules := api.Rules{
		{
			Labels:           lbls,
			EndpointSelector: api.NewESFromLabels(lblBar),
			Egress:           []api.EgressRule{{ToCIDR: []api.CIDR{"1.1.1.1/32", "2.2.2.0/24"}}},
		},
		{
			Labels:           lbls,
			EndpointSelector: api.NewESFromLabels(lblBar),
		},
	}

	_, err := ds.d.PolicyAdd(rules, nil)
	c.Assert(err, IsNil)
	ds.d.policy.Mutex.RLock()
	c.Assert(len(ds.d.policy.SearchRLocked(lbls)), Equals, 2)
	ds.d.policy.Mutex.RUnlock()
	rules[0].Egress = []api.EgressRule{{ToCIDR: []api.CIDR{"1.1.1.1/32", "2.2.2.2/32"}}}
	_, err = ds.d.PolicyAdd(rules, &policy.AddOptions{Replace: true})

	c.Assert(err, IsNil)
	ds.d.policy.Mutex.RLock()
	c.Assert(len(ds.d.policy.SearchRLocked(lbls)), Equals, 2)
	ds.d.policy.Mutex.RUnlock()

	// Updating of prefix lengths may complete *after* PolicyAdd returns. Add a
	// wait for prefix lengths to be correct after timeout to ensure that we
	// do not assert before the releasing of CIDRs has been performed.
	testutils.WaitUntil(func() bool {
		_, s4 := ds.d.prefixLengths.ToBPFData()
		sort.Ints(s4)
		if len(s4) != 2 {
			c.Logf("IPv4 Prefix lengths incorrect (expected [0, 32]). This may be because CIDRs were not released on replace. %+v", s4)
			return false
		}
		for i, v := range []int{0, 32} {
			if s4[i] != v {
				c.Logf("Unexpected IPv4 Prefix length. This may be because CIDRs were not released on replace. %+v", s4)
				return false
			}
		}
		return true
	}, time.Second*5)
}

func (ds *DaemonSuite) TestRemovePolicy(c *C) {
	qaBarLbls := labels.Labels{lblBar.Key: lblBar, lblQA.Key: lblQA}
	qaBarSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), qaBarLbls, true)
	c.Assert(err, Equals, nil)
	defer ds.d.identityAllocator.Release(context.Background(), qaBarSecLblsCtx)

	rules := api.Rules{
		{
			EndpointSelector: api.NewESFromLabels(lblBar),
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(lblJoe),
						api.NewESFromLabels(lblPete),
						api.NewESFromLabels(lblFoo),
					},
				},
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(lblFoo),
					},
					ToPorts: []api.PortRule{
						// Allow Port 80 GET /bar
						CNPAllowGETbar,
					},
				},
			},
		},
		{
			EndpointSelector: api.NewESFromLabels(lblQA),
			Ingress: []api.IngressRule{
				{
					FromRequires: []api.EndpointSelector{
						api.NewESFromLabels(lblQA),
					},
				},
			},
		},
		{
			EndpointSelector: api.NewESFromLabels(lblProd),
			Ingress: []api.IngressRule{
				{
					FromRequires: []api.EndpointSelector{
						api.NewESFromLabels(lblProd),
					},
				},
			},
		},
	}

	ds.d.l7Proxy.RemoveAllNetworkPolicies()

	_, err3 := ds.d.PolicyAdd(rules, nil)
	c.Assert(err3, Equals, nil)

	cleanup, err2 := prepareEndpointDirs()
	c.Assert(err2, Equals, nil)
	defer cleanup()

	// Create the endpoint and generate its policy.
	e := ds.prepareEndpoint(c, qaBarSecLblsCtx, true)

	// Check that the policy has been updated in the xDS cache for the L7
	// proxies.
	networkPolicies := ds.getXDSNetworkPolicies(c, nil)
	c.Assert(networkPolicies, HasLen, 2)
	qaBarNetworkPolicy := networkPolicies[QAIPv4Addr.String()]
	c.Assert(qaBarNetworkPolicy, Not(IsNil))

	// Delete the endpoint.
	e.Delete(ds.d, ds.d.ipam, &dummyManager{}, endpoint.DeleteConfig{})

	// Check that the policy has been removed from the xDS cache.
	networkPolicies = ds.getXDSNetworkPolicies(c, nil)
	c.Assert(networkPolicies, HasLen, 0)
}

type dummyManager struct{}

func (d *dummyManager) AllocateID(id uint16) (uint16, error) {
	return uint16(1), nil
}

func (d *dummyManager) RunK8sCiliumEndpointSync(*endpoint.Endpoint) {
}

func (d *dummyManager) UpdateReferences(map[id.PrefixType]string, *endpoint.Endpoint) {
}

func (d *dummyManager) UpdateIDReference(*endpoint.Endpoint) {
}

func (d *dummyManager) RemoveReferences(map[id.PrefixType]string) {
}

func (d *dummyManager) RemoveID(uint16) {
}

func (d *dummyManager) ReleaseID(*endpoint.Endpoint) error {
	return nil
}

func (ds *DaemonSuite) TestIncrementalPolicy(c *C) {
	qaBarLbls := labels.Labels{lblBar.Key: lblBar, lblQA.Key: lblQA}
	qaBarSecLblsCtx, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), qaBarLbls, true)
	c.Assert(err, Equals, nil)
	defer ds.d.identityAllocator.Release(context.Background(), qaBarSecLblsCtx)

	rules := api.Rules{
		{
			EndpointSelector: api.NewESFromLabels(lblBar),
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(lblJoe),
						api.NewESFromLabels(lblPete),
						api.NewESFromLabels(lblFoo),
					},
				},
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(lblFoo),
					},
					ToPorts: []api.PortRule{
						// Allow Port 80 GET /bar
						CNPAllowGETbar,
					},
				},
			},
		},
		{
			EndpointSelector: api.NewESFromLabels(lblQA),
			Ingress: []api.IngressRule{
				{
					FromRequires: []api.EndpointSelector{
						api.NewESFromLabels(lblQA),
					},
				},
			},
		},
		{
			EndpointSelector: api.NewESFromLabels(lblProd),
			Ingress: []api.IngressRule{
				{
					FromRequires: []api.EndpointSelector{
						api.NewESFromLabels(lblProd),
					},
				},
			},
		},
	}

	ds.d.l7Proxy.RemoveAllNetworkPolicies()

	_, err3 := ds.d.PolicyAdd(rules, nil)
	c.Assert(err3, Equals, nil)

	cleanup, err2 := prepareEndpointDirs()
	c.Assert(err2, Equals, nil)
	defer cleanup()

	// Create the endpoint and generate its policy.
	e := ds.prepareEndpoint(c, qaBarSecLblsCtx, true)

	// Check that the policy has been updated in the xDS cache for the L7
	// proxies.
	networkPolicies := ds.getXDSNetworkPolicies(c, nil)
	c.Assert(networkPolicies, HasLen, 2)
	qaBarNetworkPolicy := networkPolicies[QAIPv4Addr.String()]
	c.Assert(qaBarNetworkPolicy, Not(IsNil))

	c.Assert(qaBarNetworkPolicy.IngressPerPortPolicies, HasLen, 0)

	// Allocate identities needed for this test
	qaFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblQA.Key: lblQA}
	qaFooID, _, err := ds.d.identityAllocator.AllocateIdentity(context.Background(), qaFooLbls, true)
	c.Assert(err, Equals, nil)
	defer ds.d.identityAllocator.Release(context.Background(), qaFooID)

	// Regenerate endpoint
	ds.regenerateEndpoint(c, e)

	// Check that the policy has been updated in the xDS cache for the L7
	// proxies. The plumbing of the identity when `AllocateIdentity` is performed
	// down to the `SelectorCache` is asynchronous, so use waiting with a
	// timeout.
	err = testutils.WaitUntil(func() bool {
		networkPolicies = ds.getXDSNetworkPolicies(c, nil)
		if len(networkPolicies) != 2 {
			return false
		}
		qaBarNetworkPolicy = networkPolicies[QAIPv4Addr.String()]
		return qaBarNetworkPolicy != nil && len(qaBarNetworkPolicy.IngressPerPortPolicies) == 1
	}, time.Second*1)
	c.Assert(err, IsNil)
	c.Assert(qaBarNetworkPolicy.IngressPerPortPolicies[0].Rules, HasLen, 1)
	c.Assert(qaBarNetworkPolicy.IngressPerPortPolicies[0].Rules[0].RemotePolicies, HasLen, 1)
	c.Assert(qaBarNetworkPolicy.IngressPerPortPolicies[0].Rules[0].RemotePolicies[0], Equals, uint64(qaFooID.ID))

	// Delete the endpoint.
	e.Delete(ds.d, ds.d.ipam, &dummyManager{}, endpoint.DeleteConfig{})

	// Check that the policy has been removed from the xDS cache.
	networkPolicies = ds.getXDSNetworkPolicies(c, nil)
	c.Assert(networkPolicies, HasLen, 0)
}

func (ds *DaemonSuite) Test_addCiliumNetworkPolicyV2(c *C) {
	back := option.Config.DisableCNPStatusUpdates
	defer func() {
		option.Config.DisableCNPStatusUpdates = back
	}()
	option.Config.DisableCNPStatusUpdates = true

	uuid := k8sTypes.UID("13bba160-ddca-13e8-b697-0800273b04ff")
	type args struct {
		ciliumV2Store cache.Store
		cnp           *types.SlimCNP
		repo          *policy.Repository
	}
	type wanted struct {
		err  error
		repo *policy.Repository
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() wanted
	}{
		{
			name: "simple policy added",
			setupArgs: func() args {
				return args{
					ciliumV2Store: &cache.FakeCustomStore{},
					cnp: &types.SlimCNP{
						CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "db",
								Namespace: "production",
								UID:       uuid,
							},
							Spec: &api.Rule{
								EndpointSelector: api.EndpointSelector{
									LabelSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"env": "cluster-1",
										},
									},
								},
							},
						},
					},
					repo: policy.NewPolicyRepository(nil, nil),
				}
			},
			setupWanted: func() wanted {
				r := policy.NewPolicyRepository(nil, nil)
				r.AddList(api.Rules{
					api.NewRule().
						WithEndpointSelector(api.EndpointSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						}).
						WithIngressRules(nil).
						WithEgressRules(nil).
						WithLabels(utils.GetPolicyLabels(
							"production",
							"db",
							uuid,
							utils.ResourceTypeCiliumNetworkPolicy),
						),
				})
				return wanted{
					err:  nil,
					repo: r,
				}
			},
		},
		{
			name: "have a rule with user labels and update it without user labels, all other rules should be deleted",
			setupArgs: func() args {
				r := policy.NewPolicyRepository(nil, nil)
				lbls := utils.GetPolicyLabels("production", "db", uuid, utils.ResourceTypeCiliumNetworkPolicy)
				lbls = append(lbls, labels.ParseLabelArray("foo=bar")...).Sort()
				r.AddList(api.Rules{
					{
						EndpointSelector: api.EndpointSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						},
						Ingress:     nil,
						Egress:      nil,
						Labels:      lbls,
						Description: "",
					},
				})
				return args{
					ciliumV2Store: &cache.FakeCustomStore{},
					cnp: &types.SlimCNP{
						CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "db",
								Namespace: "production",
								UID:       uuid,
							},
							Spec: &api.Rule{
								EndpointSelector: api.EndpointSelector{
									LabelSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"env": "cluster-1",
										},
									},
								},
							},
						},
					},
					repo: r,
				}
			},
			setupWanted: func() wanted {
				r := policy.NewPolicyRepository(nil, nil)
				r.AddList(api.Rules{
					api.NewRule().
						WithEndpointSelector(api.EndpointSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						}).
						WithIngressRules(nil).
						WithEgressRules(nil).
						WithLabels(utils.GetPolicyLabels(
							"production",
							"db",
							uuid,
							utils.ResourceTypeCiliumNetworkPolicy,
						)),
				})
				return wanted{
					err:  nil,
					repo: r,
				}
			},
		},
		{
			name: "have a rule without user labels and update it with user labels, all other rules should be deleted",
			setupArgs: func() args {
				r := policy.NewPolicyRepository(nil, nil)
				r.AddList(api.Rules{
					{
						EndpointSelector: api.EndpointSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						},
						Ingress:     nil,
						Egress:      nil,
						Labels:      utils.GetPolicyLabels("production", "db", uuid, utils.ResourceTypeCiliumNetworkPolicy),
						Description: "",
					},
				})
				return args{
					ciliumV2Store: &cache.FakeCustomStore{},
					cnp: &types.SlimCNP{
						CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "db",
								Namespace: "production",
								UID:       uuid,
							},
							Spec: &api.Rule{
								EndpointSelector: api.EndpointSelector{
									LabelSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"env": "cluster-1",
										},
									},
								},
								Labels: labels.ParseLabelArray("foo=bar"),
							},
						},
					},
					repo: r,
				}
			},
			setupWanted: func() wanted {
				r := policy.NewPolicyRepository(nil, nil)
				lbls := utils.GetPolicyLabels("production", "db", uuid, utils.ResourceTypeCiliumNetworkPolicy)
				lbls = append(lbls, labels.ParseLabelArray("foo=bar")...).Sort()
				r.AddList(api.Rules{
					api.NewRule().
						WithEndpointSelector(api.EndpointSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						}).
						WithIngressRules(nil).
						WithEgressRules(nil).
						WithLabels(lbls),
				})
				return wanted{
					err:  nil,
					repo: r,
				}
			},
		},
		{
			name: "have a rule policy installed with multiple rules and apply an empty spec should delete all rules installed",
			setupArgs: func() args {
				r := policy.NewPolicyRepository(nil, nil)
				r.AddList(api.Rules{
					{
						EndpointSelector: api.EndpointSelector{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "cluster-1",
									labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
								},
							},
						},
						Ingress: []api.IngressRule{
							{
								FromEndpoints: []api.EndpointSelector{
									{
										LabelSelector: &metav1.LabelSelector{
											MatchLabels: map[string]string{
												"env": "cluster-1",
												labels.LabelSourceK8s + "." + k8sConst.PodNamespaceLabel: "production",
											},
										},
									},
								},
							},
						},
						Egress:      nil,
						Labels:      utils.GetPolicyLabels("production", "db", uuid, utils.ResourceTypeCiliumNetworkPolicy),
						Description: "",
					},
				})
				return args{
					ciliumV2Store: &cache.FakeCustomStore{},
					cnp: &types.SlimCNP{
						CiliumNetworkPolicy: &v2.CiliumNetworkPolicy{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "db",
								Namespace: "production",
								UID:       uuid,
							},
						},
					},
					repo: r,
				}
			},
			setupWanted: func() wanted {
				r := policy.NewPolicyRepository(nil, nil)
				r.AddList(api.Rules{})
				return wanted{
					err:  nil,
					repo: r,
				}
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		ds.d.policy = args.repo

		rules, policyImportErr := args.cnp.Parse()
		c.Assert(policyImportErr, IsNil)
		policyImportErr = k8s.PreprocessRules(rules, &ds.d.k8sWatcher.K8sSvcCache)
		c.Assert(policyImportErr, IsNil)
		_, policyImportErr = ds.d.PolicyAdd(rules, &policy.AddOptions{
			ReplaceWithLabels: args.cnp.GetIdentityLabels(),
			Source:            metrics.LabelEventSourceK8s,
		})
		c.Assert(policyImportErr, IsNil)

		c.Assert(args.repo.GetRulesList().Policy, checker.DeepEquals, want.repo.GetRulesList().Policy, Commentf("Test name: %q", tt.name))
	}
}
