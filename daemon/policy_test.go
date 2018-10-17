// Copyright 2016-2018 Authors of Cilium
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

package main

import (
	"os"
	"sort"
	"time"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/envoy/cilium"
	envoy_api_v2_core "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
	envoy_api_v2_route "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/route"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/gogo/protobuf/sortkeys"
	. "gopkg.in/check.v1"
)

var (
	QAHardAddr      = mac.MAC{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	QAIPv6Addr, _   = addressing.NewCiliumIPv6("beef:beef:beef:beef:aaaa:aaaa:1111:1112")
	QAIPv4Addr, _   = addressing.NewCiliumIPv4("10.11.12.13")
	ProdHardAddr    = mac.MAC{0x01, 0x07, 0x08, 0x09, 0x0a, 0x0b}
	ProdIPv6Addr, _ = addressing.NewCiliumIPv6("cafe:cafe:cafe:cafe:aaaa:aaaa:1111:1112")
	ProdIPv4Addr, _ = addressing.NewCiliumIPv4("10.11.12.14")

	regenContext = endpoint.NewRegenerationContext("test")
)

// getXDSNetworkPolicies returns the representation of the xDS network policies
// as a map of IP addresses to NetworkPolicy objects
func (ds *DaemonSuite) getXDSNetworkPolicies(c *C, resourceNames []string) map[string]*cilium.NetworkPolicy {
	networkPolicies, err := ds.d.l7Proxy.GetNetworkPolicies(resourceNames)
	c.Assert(err, IsNil)
	return networkPolicies
}

func (ds *DaemonSuite) TestUpdateConsumerMap(c *C) {
	lblProd := labels.ParseLabel("Prod")
	lblQA := labels.ParseLabel("QA")
	lblFoo := labels.ParseLabel("foo")
	lblBar := labels.ParseLabel("bar")
	lblJoe := labels.ParseLabel("user=joe")
	lblPete := labels.ParseLabel("user=pete")

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
						{
							Ports: []api.PortProtocol{
								{Port: "80", Protocol: api.ProtoTCP},
							},
							Rules: &api.L7Rules{
								HTTP: []api.PortRuleHTTP{
									{
										Path:   "/bar",
										Method: "GET",
									},
								},
							},
						},
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

	qaBarLbls := labels.Labels{lblBar.Key: lblBar, lblQA.Key: lblQA}
	qaBarSecLblsCtx, _, err := identity.AllocateIdentity(qaBarLbls)
	c.Assert(err, Equals, nil)
	defer qaBarSecLblsCtx.Release()

	prodBarLbls := labels.Labels{lblBar.Key: lblBar, lblProd.Key: lblProd}
	prodBarSecLblsCtx, _, err := identity.AllocateIdentity(prodBarLbls)
	c.Assert(err, Equals, nil)
	defer prodBarSecLblsCtx.Release()

	qaFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblQA.Key: lblQA}
	qaFooSecLblsCtx, _, err := identity.AllocateIdentity(qaFooLbls)
	c.Assert(err, Equals, nil)
	defer qaFooSecLblsCtx.Release()

	prodFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblProd.Key: lblProd}
	prodFooSecLblsCtx, _, err := identity.AllocateIdentity(prodFooLbls)
	c.Assert(err, Equals, nil)
	defer prodFooSecLblsCtx.Release()

	prodFooJoeLbls := labels.Labels{lblFoo.Key: lblFoo, lblProd.Key: lblProd, lblJoe.Key: lblJoe}
	prodFooJoeSecLblsCtx, _, err := identity.AllocateIdentity(prodFooJoeLbls)
	c.Assert(err, Equals, nil)
	defer prodFooJoeSecLblsCtx.Release()

	e := endpoint.NewEndpointWithState(1, endpoint.StateWaitingForIdentity)
	e.IfName = "dummy1"
	e.IPv6 = QAIPv6Addr
	e.IPv4 = QAIPv4Addr
	e.LXCMAC = QAHardAddr
	e.NodeMAC = QAHardAddr

	err2 := os.Mkdir("1", 755)
	c.Assert(err2, IsNil)
	defer func() {
		os.RemoveAll("1/lxc_config.h")
		time.Sleep(1 * time.Second)
		os.RemoveAll("1")
		os.RemoveAll("1_backup")
	}()
	e.SetIdentity(qaBarSecLblsCtx)
	e.UnconditionalLock()
	ready := e.SetStateLocked(endpoint.StateWaitingToRegenerate, "test")
	e.Unlock()
	c.Assert(ready, Equals, true)
	buildSuccess := <-e.Regenerate(ds.d, regenContext)
	c.Assert(buildSuccess, Equals, true)
	c.Assert(e.Allows(qaBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(prodBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.Allows(qaFooSecLblsCtx.ID), Equals, true)
	c.Assert(e.Allows(prodFooSecLblsCtx.ID), Equals, false)

	e = endpoint.NewEndpointWithState(1, endpoint.StateWaitingForIdentity)
	e.IfName = "dummy1"
	e.IPv6 = ProdIPv6Addr
	e.IPv4 = ProdIPv4Addr
	e.LXCMAC = ProdHardAddr
	e.NodeMAC = ProdHardAddr
	e.SetIdentity(prodBarSecLblsCtx)
	e.UnconditionalLock()
	ready = e.SetStateLocked(endpoint.StateWaitingToRegenerate, "test")
	e.Unlock()
	c.Assert(ready, Equals, true)
	buildSuccess = <-e.Regenerate(ds.d, regenContext)
	c.Assert(buildSuccess, Equals, true)
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
	sortkeys.Uint64s(expectedRemotePolicies)
	expectedNetworkPolicy := &cilium.NetworkPolicy{
		Name:   QAIPv4Addr.String(),
		Policy: uint64(qaBarSecLblsCtx.ID),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: envoy_api_v2_core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: expectedRemotePolicies,
						L7: &cilium.PortNetworkPolicyRule_HttpRules{
							HttpRules: &cilium.HttpNetworkPolicyRules{
								HttpRules: []*cilium.HttpNetworkPolicyRule{
									{},
								},
							},
						},
					},
					{
						RemotePolicies: expectedRemotePolicies,
						L7: &cilium.PortNetworkPolicyRule_HttpRules{
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
						},
					},
				},
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{ // Allow-all policy.
			{Protocol: envoy_api_v2_core.SocketAddress_TCP},
			{Protocol: envoy_api_v2_core.SocketAddress_UDP},
		},
	}
	c.Assert(qaBarNetworkPolicy, checker.DeepEquals, expectedNetworkPolicy)

	prodBarNetworkPolicy := networkPolicies[ProdIPv4Addr.String()]
	c.Assert(prodBarNetworkPolicy, Not(IsNil))
	expectedRemotePolicies = []uint64{
		// The qaFoo identity is allowed by FromEndpoints but rejected by
		// FromRequires, so it is not included in the remote policies:
		// uint64(qaFooSecLblsCtx.ID),
		uint64(prodFooSecLblsCtx.ID),
		uint64(prodFooJoeSecLblsCtx.ID),
	}
	sortkeys.Uint64s(expectedRemotePolicies)
	expectedRemotePolicies2 := []uint64{
		uint64(prodFooJoeSecLblsCtx.ID),
	}
	sortkeys.Uint64s(expectedRemotePolicies2)

	expectedNetworkPolicy = &cilium.NetworkPolicy{
		Name:   ProdIPv4Addr.String(),
		Policy: uint64(prodBarSecLblsCtx.ID),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: envoy_api_v2_core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: expectedRemotePolicies2,
						L7: &cilium.PortNetworkPolicyRule_HttpRules{
							HttpRules: &cilium.HttpNetworkPolicyRules{
								HttpRules: []*cilium.HttpNetworkPolicyRule{
									{},
								},
							},
						},
					},
					{
						RemotePolicies: expectedRemotePolicies,
						L7: &cilium.PortNetworkPolicyRule_HttpRules{
							HttpRules: &cilium.HttpNetworkPolicyRules{
								HttpRules: []*cilium.HttpNetworkPolicyRule{
									{},
								},
							},
						},
					},
					{
						RemotePolicies: expectedRemotePolicies,
						L7: &cilium.PortNetworkPolicyRule_HttpRules{
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
						},
					},
				},
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{ // Allow-all policy.
			{Protocol: envoy_api_v2_core.SocketAddress_TCP},
			{Protocol: envoy_api_v2_core.SocketAddress_UDP},
		},
	}
	c.Assert(prodBarNetworkPolicy, checker.DeepEquals, expectedNetworkPolicy)
}

func (ds *DaemonSuite) TestReplacePolicy(c *C) {
	lblBar := labels.ParseLabel("bar")
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
	_, err = ds.d.PolicyAdd(rules, &AddOptions{Replace: true})
	c.Assert(err, IsNil)
	ds.d.policy.Mutex.RLock()
	c.Assert(len(ds.d.policy.SearchRLocked(lbls)), Equals, 2)
	ds.d.policy.Mutex.RUnlock()

	_, s4 := ds.d.prefixLengths.ToBPFData()
	sort.Ints(s4)
	c.Assert(len(s4), Equals, 2, Commentf("IPv4 Prefix lengths incorrect (expected [0, 32]). This may be because CIDRs were not released on replace. %+v", s4))
	for i, v := range []int{0, 32} {
		c.Assert(s4[i], Equals, v, Commentf("Unexpected IPv4 Prefix length. This may be because CIDRs were not released on replace. %+v", s4))
	}
}

func (ds *DaemonSuite) TestRemovePolicy(c *C) {
	lblProd := labels.ParseLabel("Prod")
	lblQA := labels.ParseLabel("QA")
	lblFoo := labels.ParseLabel("foo")
	lblBar := labels.ParseLabel("bar")
	lblJoe := labels.ParseLabel("user=joe")
	lblPete := labels.ParseLabel("user=pete")

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
						{
							Ports: []api.PortProtocol{
								{Port: "80", Protocol: api.ProtoTCP},
							},
							Rules: &api.L7Rules{
								HTTP: []api.PortRuleHTTP{
									{
										Path:   "/bar",
										Method: "GET",
									},
								},
							},
						},
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

	qaBarLbls := labels.Labels{lblBar.Key: lblBar, lblQA.Key: lblQA}
	qaBarSecLblsCtx, _, err := identity.AllocateIdentity(qaBarLbls)
	c.Assert(err, Equals, nil)
	defer qaBarSecLblsCtx.Release()

	// Create the endpoint and generate its policy.
	e := endpoint.NewEndpointWithState(1, endpoint.StateWaitingForIdentity)
	e.IfName = "dummy1"
	e.IPv6 = QAIPv6Addr
	e.IPv4 = QAIPv4Addr
	e.LXCMAC = QAHardAddr
	e.NodeMAC = QAHardAddr
	err2 := os.Mkdir("1", 755)
	c.Assert(err2, IsNil)
	defer func() {
		os.RemoveAll("1/lxc_config.h")
		time.Sleep(1 * time.Second)
		os.RemoveAll("1")
		os.RemoveAll("1_backup")
	}()
	e.SetIdentity(qaBarSecLblsCtx)
	e.UnconditionalLock()
	ready := e.SetStateLocked(endpoint.StateWaitingToRegenerate, "test")
	e.Unlock()
	c.Assert(ready, Equals, true)
	buildSuccess := <-e.Regenerate(ds.d, regenContext)
	c.Assert(buildSuccess, Equals, true)

	// Check that the policy has been updated in the xDS cache for the L7
	// proxies.
	networkPolicies := ds.getXDSNetworkPolicies(c, nil)
	c.Assert(networkPolicies, HasLen, 2)
	qaBarNetworkPolicy := networkPolicies[QAIPv4Addr.String()]
	c.Assert(qaBarNetworkPolicy, Not(IsNil))

	// Delete the endpoint.
	e.UnconditionalLock()
	e.LeaveLocked(ds.d, nil)
	e.Unlock()

	// Check that the policy has been removed from the xDS cache.
	networkPolicies = ds.getXDSNetworkPolicies(c, nil)
	c.Assert(networkPolicies, HasLen, 0)
}
