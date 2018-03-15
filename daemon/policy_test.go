// Copyright 2016-2017 Authors of Cilium
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
	"time"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/envoy/cilium"
	envoy_api_v2_core "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
	envoy_api_v2_route "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/route"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/policy/api/v2"

	"github.com/gogo/protobuf/sortkeys"
	"github.com/golang/protobuf/ptypes/wrappers"
	. "gopkg.in/check.v1"
)

var (
	QAHardAddr      = mac.MAC{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	QAIPv6Addr, _   = addressing.NewCiliumIPv6("beef:beef:beef:beef:aaaa:aaaa:1111:1112")
	QAIPv4Addr, _   = addressing.NewCiliumIPv4("10.11.12.13")
	ProdHardAddr    = mac.MAC{0x01, 0x07, 0x08, 0x09, 0x0a, 0x0b}
	ProdIPv6Addr, _ = addressing.NewCiliumIPv6("cafe:cafe:cafe:cafe:aaaa:aaaa:1111:1112")
	ProdIPv4Addr, _ = addressing.NewCiliumIPv4("10.11.12.14")
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

	rules := v2.Rules{
		{
			EndpointSelector: v2.NewESFromLabels(lblBar),
			Ingress: []v2.IngressRule{
				{
					FromEndpoints: []v2.EndpointSelector{
						v2.NewESFromLabels(lblJoe),
						v2.NewESFromLabels(lblPete),
						v2.NewESFromLabels(lblFoo),
					},
				},
				{
					FromEndpoints: []v2.EndpointSelector{
						v2.NewESFromLabels(lblFoo),
					},
					ToPorts: []v2.PortRule{
						{
							Ports: []v2.PortProtocol{
								{Port: "80", Protocol: v2.ProtoTCP},
							},
							Rules: &v2.L7Rules{
								HTTP: []v2.PortRuleHTTP{
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
			EndpointSelector: v2.NewESFromLabels(lblQA),
			Ingress: []v2.IngressRule{
				{
					FromRequires: []v2.EndpointSelector{
						v2.NewESFromLabels(lblQA),
					},
				},
			},
		},
		{
			EndpointSelector: v2.NewESFromLabels(lblProd),
			Ingress: []v2.IngressRule{
				{
					FromRequires: []v2.EndpointSelector{
						v2.NewESFromLabels(lblProd),
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

	prodBarLbls := labels.Labels{lblBar.Key: lblBar, lblProd.Key: lblProd}
	prodBarSecLblsCtx, _, err := identity.AllocateIdentity(prodBarLbls)
	c.Assert(err, Equals, nil)

	qaFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblQA.Key: lblQA}
	qaFooSecLblsCtx, _, err := identity.AllocateIdentity(qaFooLbls)
	c.Assert(err, Equals, nil)

	prodFooLbls := labels.Labels{lblFoo.Key: lblFoo, lblProd.Key: lblProd}
	prodFooSecLblsCtx, _, err := identity.AllocateIdentity(prodFooLbls)
	c.Assert(err, Equals, nil)

	prodFooJoeLbls := labels.Labels{lblFoo.Key: lblFoo, lblProd.Key: lblProd, lblJoe.Key: lblJoe}
	prodFooJoeSecLblsCtx, _, err := identity.AllocateIdentity(prodFooJoeLbls)
	c.Assert(err, Equals, nil)

	e := endpoint.NewEndpointWithState(1, endpoint.StateWaitingForIdentity)
	e.IfName = "dummy1"
	e.IPv6 = QAIPv6Addr
	e.IPv4 = QAIPv4Addr
	e.LXCMAC = QAHardAddr
	e.NodeMAC = QAHardAddr

	err2 := os.Mkdir("1", 755)
	c.Assert(err2, IsNil)
	defer func() {
		os.RemoveAll("1/geneve_opts.cfg")
		os.RemoveAll("1/lxc_config.h")
		time.Sleep(1 * time.Second)
		os.RemoveAll("1")
		os.RemoveAll("1_backup")
	}()
	e.SetIdentity(qaBarSecLblsCtx)
	e.Mutex.Lock()
	ready := e.SetStateLocked(endpoint.StateWaitingToRegenerate, "test")
	e.Mutex.Unlock()
	c.Assert(ready, Equals, true)
	buildSuccess := <-e.Regenerate(ds.d, "test")
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
	e.Mutex.Lock()
	ready = e.SetStateLocked(endpoint.StateWaitingToRegenerate, "test")
	e.Mutex.Unlock()
	c.Assert(ready, Equals, true)
	buildSuccess = <-e.Regenerate(ds.d, "test")
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
						L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
							HttpRules: &cilium.HttpNetworkPolicyRules{
								HttpRules: []*cilium.HttpNetworkPolicyRule{
									{
										Headers: []*envoy_api_v2_route.HeaderMatcher{
											{
												Name:  ":method",
												Value: "GET",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":path",
												Value: "/bar",
												Regex: &wrappers.BoolValue{Value: true},
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
	c.Assert(qaBarNetworkPolicy, comparator.DeepEquals, expectedNetworkPolicy)

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
	expectedNetworkPolicy.Name = ProdIPv4Addr.String()
	expectedNetworkPolicy.Policy = uint64(prodBarSecLblsCtx.ID)
	expectedNetworkPolicy.IngressPerPortPolicies[0].Rules[0].RemotePolicies = expectedRemotePolicies
	c.Assert(prodBarNetworkPolicy, comparator.DeepEquals, expectedNetworkPolicy)
}

func (ds *DaemonSuite) TestReplacePolicy(c *C) {
	lblBar := labels.ParseLabel("bar")
	lbls := labels.ParseLabelArray("foo", "bar")
	rules := v2.Rules{
		{
			Labels:           lbls,
			EndpointSelector: v2.NewESFromLabels(lblBar),
		},
		{
			Labels:           lbls,
			EndpointSelector: v2.NewESFromLabels(lblBar),
		},
	}

	_, err := ds.d.PolicyAdd(rules, nil)
	c.Assert(err, IsNil)
	ds.d.policy.Mutex.RLock()
	c.Assert(len(ds.d.policy.SearchRLocked(lbls)), Equals, 2)
	ds.d.policy.Mutex.RUnlock()
	_, err = ds.d.PolicyAdd(rules, &AddOptions{Replace: true})
	c.Assert(err, IsNil)
	ds.d.policy.Mutex.RLock()
	c.Assert(len(ds.d.policy.SearchRLocked(lbls)), Equals, 2)
	ds.d.policy.Mutex.RUnlock()
}

func (ds *DaemonSuite) TestRemovePolicy(c *C) {
	lblProd := labels.ParseLabel("Prod")
	lblQA := labels.ParseLabel("QA")
	lblFoo := labels.ParseLabel("foo")
	lblBar := labels.ParseLabel("bar")
	lblJoe := labels.ParseLabel("user=joe")
	lblPete := labels.ParseLabel("user=pete")

	rules := v2.Rules{
		{
			EndpointSelector: v2.NewESFromLabels(lblBar),
			Ingress: []v2.IngressRule{
				{
					FromEndpoints: []v2.EndpointSelector{
						v2.NewESFromLabels(lblJoe),
						v2.NewESFromLabels(lblPete),
						v2.NewESFromLabels(lblFoo),
					},
				},
				{
					FromEndpoints: []v2.EndpointSelector{
						v2.NewESFromLabels(lblFoo),
					},
					ToPorts: []v2.PortRule{
						{
							Ports: []v2.PortProtocol{
								{Port: "80", Protocol: v2.ProtoTCP},
							},
							Rules: &v2.L7Rules{
								HTTP: []v2.PortRuleHTTP{
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
			EndpointSelector: v2.NewESFromLabels(lblQA),
			Ingress: []v2.IngressRule{
				{
					FromRequires: []v2.EndpointSelector{
						v2.NewESFromLabels(lblQA),
					},
				},
			},
		},
		{
			EndpointSelector: v2.NewESFromLabels(lblProd),
			Ingress: []v2.IngressRule{
				{
					FromRequires: []v2.EndpointSelector{
						v2.NewESFromLabels(lblProd),
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
		os.RemoveAll("1/geneve_opts.cfg")
		os.RemoveAll("1/lxc_config.h")
		time.Sleep(1 * time.Second)
		os.RemoveAll("1")
		os.RemoveAll("1_backup")
	}()
	e.SetIdentity(qaBarSecLblsCtx)
	e.Mutex.Lock()
	ready := e.SetStateLocked(endpoint.StateWaitingToRegenerate, "test")
	e.Mutex.Unlock()
	c.Assert(ready, Equals, true)
	buildSuccess := <-e.Regenerate(ds.d, "test")
	c.Assert(buildSuccess, Equals, true)

	// Check that the policy has been updated in the xDS cache for the L7
	// proxies.
	networkPolicies := ds.getXDSNetworkPolicies(c, nil)
	c.Assert(networkPolicies, HasLen, 2)
	qaBarNetworkPolicy := networkPolicies[QAIPv4Addr.String()]
	c.Assert(qaBarNetworkPolicy, Not(IsNil))

	// Delete the endpoint.
	e.Mutex.Lock()
	e.LeaveLocked(ds.d)
	e.Mutex.Unlock()

	// Check that the policy has been removed from the xDS cache.
	networkPolicies = ds.getXDSNetworkPolicies(c, nil)
	c.Assert(networkPolicies, HasLen, 0)
}
