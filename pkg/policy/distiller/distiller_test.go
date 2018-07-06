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

package distiller

import (
	"fmt"
	"testing"

	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
	"github.com/golang/protobuf/ptypes/wrappers"

	envoy_api_v2_route "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/route"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type ResolverTestSuite struct{}

var _ = Suite(&ResolverTestSuite{})

var (
	identity11             = identity.NumericIdentity(11)
	identity30             = identity.NumericIdentity(30)
	identity35             = identity.NumericIdentity(35)
	identitySplashBrothers = identity.NumericIdentity(41)
	identityWarriors       = identity.NumericIdentity(73)

	endpointSelectorDurant     = api.NewESFromLabels(labels.ParseSelectLabel(fmt.Sprintf("%s:%s", labels.LabelSourceK8s, "durant")))
	endpointSelectorSteph      = api.NewESFromLabels(labels.ParseSelectLabel(fmt.Sprintf("%s:%s", labels.LabelSourceK8s, "steph")))
	endpointSelectorKlay       = api.NewESFromLabels(labels.ParseSelectLabel(fmt.Sprintf("%s:%s", labels.LabelSourceK8s, "klay")))
	endpointSelectorSplashBros = api.NewESFromLabels(
		labels.ParseSelectLabel(fmt.Sprintf("%s:%s", labels.LabelSourceK8s, "steph")),
		labels.ParseSelectLabel(fmt.Sprintf("%s:%s", labels.LabelSourceK8s, "klay")))
	endpointSelectorA = api.NewESFromLabels(labels.ParseSelectLabel("id=a"))

	stephLabel  = labels.NewLabel("steph", "", labels.LabelSourceK8s)
	durantLabel = labels.NewLabel("durant", "", labels.LabelSourceK8s)
	klayLabel   = labels.NewLabel("klay", "", labels.LabelSourceK8s)

	identity11Labels = labels.LabelArray{
		klayLabel,
	}

	identity30Labels = labels.LabelArray{
		stephLabel,
	}

	identity35Labels = labels.LabelArray{
		durantLabel,
	}

	identityWarriorsLabels = labels.LabelArray{
		durantLabel,
		stephLabel,
		klayLabel,
	}

	identitySplashBrothersLabels = labels.LabelArray{
		stephLabel,
		klayLabel,
	}
)

func initIdentityCache() identity.IdentityCache {
	identityCache := identity.IdentityCache{}

	identityCache[identity11] = identity11Labels
	identityCache[identity30] = identity30Labels
	identityCache[identity35] = identity35Labels
	identityCache[identityWarriors] = identityWarriorsLabels
	identityCache[identitySplashBrothers] = identitySplashBrothersLabels

	return identityCache
}

func (ds *ResolverTestSuite) TestResolveIdentityNotInCache(c *C) {
	identityCache := initIdentityCache()
	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
				},
			},
		},
	}

	identityNotInCache := identity.NumericIdentity(23)

	// If an identity is not in the cache, return a nil policy, because we
	// cannot generate a policy for it.
	unexpectedIdentity := ResolveIdentityPolicy(rules, identityCache, identityNotInCache)
	c.Assert(unexpectedIdentity, IsNil)

}

func (ds *ResolverTestSuite) TestAllowedDeniedIdentitySets(c *C) {

	allowedIngressIdentities := identity.IdentityCache{}
	deniedIngressIdentities := identity.IdentityCache{}

	// These rules specify that we require that ingress to any endpoint with
	// endpointSelectorDurant must have endpointSelectorKlay AND
	// endpointSelectorSteph AND endpointSelectorDurant.
	rules := api.Rules{&api.Rule{
		EndpointSelector: endpointSelectorDurant,
		Ingress: []api.IngressRule{
			{
				FromRequires: []api.EndpointSelector{
					endpointSelectorKlay,
				},
			},
			{
				FromRequires: []api.EndpointSelector{
					endpointSelectorSteph,
				},
			},
			{
				FromRequires: []api.EndpointSelector{
					endpointSelectorDurant,
				},
			},
		},
	}}

	identityCache := identity.IdentityCache{}
	identityCache[identity11] = identity11Labels
	identityCache[identity30] = identity30Labels
	identityCache[identity35] = identity35Labels
	identityCache[identityWarriors] = identityWarriorsLabels

	for remoteIdentity, remoteIdentityLabels := range identityCache {
		for _, rule := range rules {
			for _, ingressRule := range rule.Ingress {
				for _, fromRequires := range ingressRule.FromRequires {
					computeAllowedAndDeniedIdentitySets(fromRequires, remoteIdentity, remoteIdentityLabels, allowedIngressIdentities, deniedIngressIdentities)
				}
			}
		}
	}

	// The only identity with all three endpointselectors speicifed in the rules,
	// is identityWarriors.
	expectedAllowedIngressIdentities := identity.IdentityCache{
		identityWarriors: identityWarriorsLabels,
	}

	// All other identities in the cache are denied because they did not meet
	// the requirements in the rules.
	expectedDeniedIngressIdentities := identity.IdentityCache{
		identity11: identity11Labels,
		identity30: identity30Labels,
		identity35: identity35Labels,
	}

	c.Assert(allowedIngressIdentities, comparator.DeepEquals, expectedAllowedIngressIdentities)
	c.Assert(deniedIngressIdentities, comparator.DeepEquals, expectedDeniedIngressIdentities)

	identityCache = identity.IdentityCache{}
	identityCache[identity11] = identity11Labels
	identityCache[identity30] = identity30Labels
	identityCache[identity35] = identity35Labels
	identityCache[identitySplashBrothers] = identitySplashBrothersLabels
	identityCache[identityWarriors] = identityWarriorsLabels

	// These rules specify that we require that ingress to any endpoint with
	// endpointSelectorSplashBros (which is comprised of endpointSelectorKlay
	// and endpointSelectorSteph) AND endpointSelectorDurant.
	rules = api.Rules{&api.Rule{
		EndpointSelector: endpointSelectorDurant,
		Ingress: []api.IngressRule{
			{
				FromRequires: []api.EndpointSelector{
					endpointSelectorSplashBros,
				},
			},
			{
				FromRequires: []api.EndpointSelector{
					endpointSelectorDurant,
				},
			},
		},
	}}

	for remoteIdentity, remoteIdentityLabels := range identityCache {
		for _, rule := range rules {
			for _, ingressRule := range rule.Ingress {
				for _, fromRequires := range ingressRule.FromRequires {
					computeAllowedAndDeniedIdentitySets(fromRequires, remoteIdentity, remoteIdentityLabels, allowedIngressIdentities, deniedIngressIdentities)
				}
			}
		}
	}

	expectedAllowedIngressIdentities = identity.IdentityCache{
		identityWarriors: identityWarriorsLabels,
	}

	expectedDeniedIngressIdentities = identity.IdentityCache{
		identity11:             identity11Labels,
		identity30:             identity30Labels,
		identity35:             identity35Labels,
		identitySplashBrothers: identitySplashBrothersLabels,
	}

	c.Assert(allowedIngressIdentities, comparator.DeepEquals, expectedAllowedIngressIdentities)
	c.Assert(deniedIngressIdentities, comparator.DeepEquals, expectedDeniedIngressIdentities)

}
func (ds *ResolverTestSuite) TestComputeRemotePolicies(c *C) {
	endpointSelectorDurant := api.NewESFromLabels(labels.ParseSelectLabel(fmt.Sprintf("%s:%s", labels.LabelSourceK8s, "durant")))
	uint64Identity35 := uint64(35)
	numericIdentity35 := identity.NumericIdentity(35)
	numericIdentity23 := identity.NumericIdentity(23)

	// Case 1: endpoint selector selects all at L3, and there are no denied
	// identities; can be allowed at L3. Allow-all is treated as an empty list
	// of remote policies.
	remotePolicies := computeRemotePolicies(api.WildcardEndpointSelector, numericIdentity35, identity.IdentityCache{})
	c.Assert(len(remotePolicies), Equals, 0)

	// Case 2: Despite wildcarding at L3, still need to specify identity
	// explicitly due to presence of denied identities.
	remotePolicies = computeRemotePolicies(api.WildcardEndpointSelector, numericIdentity35, identity.IdentityCache{numericIdentity23: labels.LabelArray{}})
	c.Assert(len(remotePolicies), Equals, 1)
	c.Assert(remotePolicies[0], Equals, uint64Identity35)

	// Case 3: no wildcarding at L3, and no denied identities; must specify that
	// only remote policy which is allowed is the one provided to the function.
	remotePolicies = computeRemotePolicies(endpointSelectorDurant, numericIdentity35, identity.IdentityCache{})
	c.Assert(len(remotePolicies), Equals, 1)
	c.Assert(remotePolicies[0], Equals, uint64Identity35)

	// Case 4: no wildcarding at L3, and denied identities; must specify that
	// only remote policy which is allowed is the one provided to the function.
	remotePolicies = computeRemotePolicies(endpointSelectorDurant, numericIdentity35, identity.IdentityCache{numericIdentity23: labels.LabelArray{}})
	c.Assert(len(remotePolicies), Equals, 1)
	c.Assert(remotePolicies[0], Equals, uint64Identity35)
}

func (ds *ResolverTestSuite) TestResolveIdentityPolicyL3Only(c *C) {
	identityCache := initIdentityCache()

	// Allow all at L3 from any endpoint which contains the labels in
	// endpointSelectorSplashBros. Because that contains labels stephLabel
	// and klayLabel, we expect to allow all ingress from identities
	// identitySplashBros and identityWarriors, which both contain these labels.
	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						endpointSelectorSplashBros,
					},
				},
			},
		},
	}
	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)

	// ProtocolWildcard is "true" because rule does not restrict for protocol
	// at L4.
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
					},
				},
				ProtocolWildcard: true,
			},
			{
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
				ProtocolWildcard: true,
			},
		},
	}
	c.Assert(expectedPolicy, comparator.DeepEquals, splashBrothersPolicy)

	// Allow ingress from all endpoints with labels contained in
	// endpointSelectorSplashBros OR endpointSelectorDurant.
	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						endpointSelectorSplashBros,
					},
				},
				{
					FromEndpoints: []api.EndpointSelector{
						endpointSelectorDurant,
					},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)

	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identity35)},
					},
				},
				ProtocolWildcard: true,
			},
			{
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
					},
				},
				ProtocolWildcard: true,
			},
			{
				// This PortNetworkPolicy is synthesized from the rule where
				// endpointSelectorSplashBros is listed as the requirement at
				// L3.
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
				ProtocolWildcard: true,
			},
			{
				// This PortNetworkPolicy is synthesized from the rule where
				// endpointSelectorDurant is listed as the requirement at L3.
				// We allow duplicates in PortNetworkPolicy at this point in time.
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
				ProtocolWildcard: true,
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)
}
func (ds *ResolverTestSuite) TestResolveIdentityPolicyL4Only(c *C) {
	identityCache := initIdentityCache()

	// Allow all at port 80 from any endpoint.
	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				// Empty list of rules is present here because an empty list of
				// rules mean all flows are allowed by this predicate.
				Rules: []*cilium.PortNetworkPolicyRule{},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	// Egress policy.
	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Egress: []api.EgressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules:    []*cilium.PortNetworkPolicyRule{},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
							{Port: "53", Protocol: api.ProtoUDP},
							{Port: "8080", Protocol: api.ProtoAny},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules:    []*cilium.PortNetworkPolicyRule{},
			},
			{
				// api.ProtoAny equates to allowing for TCP and UDP.
				Port:     8080,
				Protocol: core.SocketAddress_TCP,
				Rules:    []*cilium.PortNetworkPolicyRule{},
			},
			{
				Port:     53,
				Protocol: core.SocketAddress_UDP,
				Rules:    []*cilium.PortNetworkPolicyRule{},
			},
			{
				Port:     8080,
				Protocol: core.SocketAddress_UDP,
				Rules:    []*cilium.PortNetworkPolicyRule{},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	// pkg/policy/l4_filter_test.go:TestMergeAllowAllL3AndAllowAllL7 Case 1A
	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}

	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)

	// Duplicate rules should result in duplicate PortNetworkPolicy rules being
	// generated.
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules:    []*cilium.PortNetworkPolicyRule{},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules:    []*cilium.PortNetworkPolicyRule{},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	// pkg/policy/l4_filter_test.go:TestMergeAllowAllL3AndAllowAllL7 Case 1B

	// Rules are the same as above, but with an empty endpoint selector list
	// for FromEndpoints as opposed to the wildcard endpoint selector.
	// The generated NetworkPolicy should be the same.
	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules:    []*cilium.PortNetworkPolicyRule{},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules:    []*cilium.PortNetworkPolicyRule{},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)
}
func (ds *ResolverTestSuite) TestMergeAllowAllL3AndAllowAllL7(c *C) {
	identityCache := initIdentityCache()

	// pkg/policy/l4_filter_test.go:TestMergeAllowAllL3AndAllowAllL7 Case 2A
	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)

	// The generated policy directly corresponds with the added rules. Note
	// that this policy is not yet optimized to simply allow all at Layer 7
	// for HTTP.
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules:    []*cilium.PortNetworkPolicyRule{},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
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
												Value: "/",
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
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	// pkg/policy/l4_filter_test.go:TestMergeAllowAllL3AndAllowAllL7 Case 2B,
	// for HTTP.

	// Inverse order of prior case. Should result in the same policy.
	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules:    []*cilium.PortNetworkPolicyRule{},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
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
												Value: "/",
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
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	// pkg/policy/l4_filter_test.go:TestMergeAllowAllL3AndAllowAllL7 Case 2B,
	// but for Kafka.
	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							Kafka: []api.PortRuleKafka{
								{
									APIVersion: "1",
									APIKey:     "createtopics",
									Topic:      "foo",
								},
							},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules:    []*cilium.PortNetworkPolicyRule{},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						L7Rules: &cilium.PortNetworkPolicyRule_KafkaRules{
							KafkaRules: &cilium.KafkaNetworkPolicyRules{
								KafkaRules: []*cilium.KafkaNetworkPolicyRule{
									{
										ApiVersion: 1,
										ApiKey:     19,
										Topic:      "foo",
										ClientId:   "",
									},
								},
							},
						},
					},
				},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)
}

// Case 3: allow all at L3 in both rules. Both rules have same parser type and
// same API resource specified at L7 for HTTP.
func (ds *ResolverTestSuite) TestMergeIdenticalAllowAllL3AndRestrictedL7HTTP(c *C) {
	identityCache := initIdentityCache()

	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)

	// Duplicate PortNetworkPolicy rules are generated.
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
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
												Value: "/",
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
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
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
												Value: "/",
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
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)
}

// Case 4: identical allow all at L3 with identical restrictions on Kafka.
func (ds *ResolverTestSuite) TestMergeIdenticalAllowAllL3AndRestrictedL7Kafka(c *C) {
	identityCache := initIdentityCache()

	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: api.EndpointSelectorSlice{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "9092", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							Kafka: []api.PortRuleKafka{
								{Topic: "foo"},
							},
						},
					}},
				},
				{
					FromEndpoints: api.EndpointSelectorSlice{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "9092", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							Kafka: []api.PortRuleKafka{
								{Topic: "foo"},
							},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)

	// Duplicate PortNetworkPolicy rules are generated.
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     9092,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						L7Rules: &cilium.PortNetworkPolicyRule_KafkaRules{
							KafkaRules: &cilium.KafkaNetworkPolicyRules{
								KafkaRules: []*cilium.KafkaNetworkPolicyRule{
									{
										ApiVersion: -1,
										ApiKey:     -1,
										// Topic is empty because all requests
										// are allowed if APIKey is not specified
										// in api.PortRuleKafka.
										Topic:    "",
										ClientId: "",
									},
								},
							},
						},
					},
				},
			},
			{
				Port:     9092,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						L7Rules: &cilium.PortNetworkPolicyRule_KafkaRules{
							KafkaRules: &cilium.KafkaNetworkPolicyRules{
								KafkaRules: []*cilium.KafkaNetworkPolicyRule{
									{
										ApiVersion: -1,
										ApiKey:     -1,
										Topic:      "",
										ClientId:   "",
									},
								},
							},
						},
					},
				},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	// Same as above, but specify an APIKey in the Kafka rule.
	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: api.EndpointSelectorSlice{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "9092", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							Kafka: []api.PortRuleKafka{
								{
									APIKey: "produce",
									Topic:  "foo",
								},
							},
						},
					}},
				},
				{
					FromEndpoints: api.EndpointSelectorSlice{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "9092", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							Kafka: []api.PortRuleKafka{
								{
									APIKey: "produce",
									Topic:  "foo",
								},
							},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     9092,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						L7Rules: &cilium.PortNetworkPolicyRule_KafkaRules{
							KafkaRules: &cilium.KafkaNetworkPolicyRules{
								KafkaRules: []*cilium.KafkaNetworkPolicyRule{
									{
										ApiVersion: -1,
										ApiKey:     0,
										Topic:      "foo",
										ClientId:   "",
									},
								},
							},
						},
					},
				},
			},
			{
				Port:     9092,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						L7Rules: &cilium.PortNetworkPolicyRule_KafkaRules{
							KafkaRules: &cilium.KafkaNetworkPolicyRules{
								KafkaRules: []*cilium.KafkaNetworkPolicyRule{
									{
										ApiVersion: -1,
										ApiKey:     0,
										Topic:      "foo",
										ClientId:   "",
									},
								},
							},
						},
					},
				},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)
}

// Case 5: use conflicting protocols on the same port in different rules. The
// initial resolved policy will generate rules that conflict. This is still
// allowed, though, at the initial translation from Rules to NetworkPolicy.
func (ds *ResolverTestSuite) TestConflictingL7OnSamePort(c *C) {
	identityCache := initIdentityCache()

	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{endpointSelectorSplashBros},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							Kafka: []api.PortRuleKafka{
								{Topic: "foo"},
							},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)

	// Note that the expectedPolicy here contains PortNetworkPolicies which
	// have conflicting parsers on the same port. We allow this while resolving
	// the policy. When optimizing (which will come after resolving), we will
	// error out if a conflict is discovered.
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
						L7Rules: &cilium.PortNetworkPolicyRule_KafkaRules{
							KafkaRules: &cilium.KafkaNetworkPolicyRules{
								KafkaRules: []*cilium.KafkaNetworkPolicyRule{
									{
										ApiVersion: -1,
										ApiKey:     -1,
										// Topic is empty because all requests
										// are allowed if APIKey is not specified
										// in api.PortRuleKafka.
										Topic:    "",
										ClientId: "",
									},
								},
							},
						},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
						L7Rules: &cilium.PortNetworkPolicyRule_KafkaRules{
							KafkaRules: &cilium.KafkaNetworkPolicyRules{
								KafkaRules: []*cilium.KafkaNetworkPolicyRule{
									{
										ApiVersion: -1,
										ApiKey:     -1,
										Topic:      "",
										ClientId:   "",
									},
								},
							},
						},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
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
												Value: "/",
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
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	// Test reverse order to ensure that we error out if HTTP rule has already
	// been parsed, and then we hit a Kafka rule applying at the same port.
	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{endpointSelectorSplashBros},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							Kafka: []api.PortRuleKafka{
								{Topic: "foo"},
							},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)

	// Note that the expectedPolicy here contains PortNetworkPolicies which
	// have conflicting parsers on the same port. We allow this while resolving
	// the policy. When optimizing (which will come after resolving), we will
	// error out if a conflict is discovered.
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
						L7Rules: &cilium.PortNetworkPolicyRule_KafkaRules{
							KafkaRules: &cilium.KafkaNetworkPolicyRules{
								KafkaRules: []*cilium.KafkaNetworkPolicyRule{
									{
										ApiVersion: -1,
										ApiKey:     -1,
										// Topic is empty because all requests
										// are allowed if APIKey is not specified
										// in api.PortRuleKafka.
										Topic:    "",
										ClientId: "",
									},
								},
							},
						},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
						L7Rules: &cilium.PortNetworkPolicyRule_KafkaRules{
							KafkaRules: &cilium.KafkaNetworkPolicyRules{
								KafkaRules: []*cilium.KafkaNetworkPolicyRule{
									{
										ApiVersion: -1,
										ApiKey:     -1,
										Topic:      "",
										ClientId:   "",
									},
								},
							},
						},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
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
												Value: "/",
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
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

}

// Case 6: allow all at L3/L7 in one rule, and select an endpoint and allow all on L7
// in another rule.
// TODO: Should resolve to just allowing all on L3/L7 (first rule  shadows the
// second) after optimization.
func (ds *ResolverTestSuite) TestL3RuleShadowedByL3AllowAll(c *C) {
	identityCache := initIdentityCache()

	// Case 6A: Specify WildcardEndpointSelector explicitly.
	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{endpointSelectorDurant},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}

	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				// Empty list of Rules corresponds to wildcarding all L3 and
				// L7 for this port.
				Rules: []*cilium.PortNetworkPolicyRule{},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						// From endpointSelectorDurant.
						RemotePolicies: []uint64{uint64(identity35)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						// From endpointSelectorDurant.
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)
}

// Case 7: allow all at L3/L7 in one rule, and in another rule, select an endpoint
// which restricts on L7.
// TODO: after optimization, should resolve to just allowing all on L3/L7 (first rule
// shadows the second), but setting traffic to the HTTP proxy.
func (ds *ResolverTestSuite) TestL3RuleWithL7RulePartiallyShadowedByL3AllowAll(c *C) {
	identityCache := initIdentityCache()

	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{endpointSelectorSplashBros},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}

	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules:    []*cilium.PortNetworkPolicyRule{},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
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
												Value: "/",
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
			{
				// Same as prior PortNetworkPolicy, but is generated for
				// identityWarriors.
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
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
												Value: "/",
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
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{endpointSelectorSplashBros},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
			},
		},
	}

	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules:    []*cilium.PortNetworkPolicyRule{},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
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
												Value: "/",
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
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
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
												Value: "/",
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
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)
}

// Case 8: allow all at L3 and restricts on L7 in one rule, and in another rule,
// select an endpoint which restricts the same as the first rule on L7.
// TODO: after optimizing, should resolve to just allowing all on L3, but restricting on L7 for both
// wildcard and the specified endpoint.
func (ds *ResolverTestSuite) TestL3RuleWithL7RuleShadowedByL3AllowAll(c *C) {
	identityCache := initIdentityCache()

	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{endpointSelectorSplashBros},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
			},
		},
	}

	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
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
												Value: "/",
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
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
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
												Value: "/",
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
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
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
												Value: "/",
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
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)
}

// Case 9: allow all at L3 and restricts on L7 in one rule, and in another rule,
// select an endpoint which restricts on different L7 protocol.
// TODO: after optimization, should fail as cannot have conflicting parsers on same port.
func (ds *ResolverTestSuite) TestL3SelectingEndpointAndL3AllowAllMergeConflictingL7(c *C) {
	identityCache := initIdentityCache()
	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{endpointSelectorSplashBros},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							Kafka: []api.PortRuleKafka{
								{Topic: "foo"},
							},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
			},
		},
	}

	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
						L7Rules: &cilium.PortNetworkPolicyRule_KafkaRules{
							KafkaRules: &cilium.KafkaNetworkPolicyRules{
								KafkaRules: []*cilium.KafkaNetworkPolicyRule{
									{
										ApiKey:     -1,
										ApiVersion: -1,
										Topic:      "",
										ClientId:   "",
									},
								},
							},
						},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
						L7Rules: &cilium.PortNetworkPolicyRule_KafkaRules{
							KafkaRules: &cilium.KafkaNetworkPolicyRules{
								KafkaRules: []*cilium.KafkaNetworkPolicyRule{
									{
										ApiKey:     -1,
										ApiVersion: -1,
										Topic:      "",
										ClientId:   "",
									},
								},
							},
						},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
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
												Value: "/",
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
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{endpointSelectorSplashBros},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							Kafka: []api.PortRuleKafka{
								{Topic: "foo"},
							},
						},
					}},
				},
			},
		},
	}

	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
						L7Rules: &cilium.PortNetworkPolicyRule_KafkaRules{
							KafkaRules: &cilium.KafkaNetworkPolicyRules{
								KafkaRules: []*cilium.KafkaNetworkPolicyRule{
									{
										ApiKey:     -1,
										ApiVersion: -1,
										Topic:      "",
										ClientId:   "",
									},
								},
							},
						},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
						L7Rules: &cilium.PortNetworkPolicyRule_KafkaRules{
							KafkaRules: &cilium.KafkaNetworkPolicyRules{
								KafkaRules: []*cilium.KafkaNetworkPolicyRule{
									{
										ApiKey:     -1,
										ApiVersion: -1,
										Topic:      "",
										ClientId:   "",
									},
								},
							},
						},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
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
												Value: "/",
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
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

}

// Case 10: restrict same path / method on L7 in both rules,
// but select different endpoints in each rule.
func (ds *ResolverTestSuite) TestMergingWithDifferentEndpointsSelectedAllowSameL7(c *C) {
	identityCache := identity.IdentityCache{}

	identityCache[identity11] = identity11Labels
	identityCache[identity30] = identity30Labels
	identityCache[identity35] = identity35Labels

	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorKlay,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{endpointSelectorDurant},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{endpointSelectorSteph},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
			},
		},
	}

	klayPolicy := ResolveIdentityPolicy(rules, identityCache, identity11)
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identity11),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identity30)},
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
												Value: "/",
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
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identity35)},
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
												Value: "/",
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
	}
	c.Assert(klayPolicy, comparator.DeepEquals, expectedPolicy)
}

// Case 11: allow all on L7 in both rules, but select different endpoints in each rule.
func (ds *ResolverTestSuite) TestMergingWithDifferentEndpointSelectedAllowAllL7(c *C) {
	identityCache := initIdentityCache()

	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{endpointSelectorSteph},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{endpointSelectorDurant},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}

	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identity30)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identity35)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)
}

// Test L3-dependent L4 policy.
func (ds *ResolverTestSuite) TestResolveIdentityPolicyL3L4(c *C) {
	identityCache := initIdentityCache()

	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							durantLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identity35)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
			{
				// This duplicate rule appears twice because both rules match
				// the labels for identityWarriors.
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							durantLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identity35)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
			{
				// This duplicate rule appears twice because both rules match
				// the labels for identityWarriors.
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							durantLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "81", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
			{
				Port:     81,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identity35)},
					},
				},
			},
			{
				Port:     81,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							durantLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "81", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules:    []*cilium.PortNetworkPolicyRule{},
			},
			{
				Port:     81,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identity35)},
					},
				},
			},
			{
				Port:     81,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
				},
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							durantLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "81", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
					},
				},
				ProtocolWildcard: true,
			},

			{
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
				ProtocolWildcard: true,
			},
			{
				Port:     81,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identity35)},
					},
				},
			},
			{
				Port:     81,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)
}
func (ds *ResolverTestSuite) TestResolveIdentityPolicyL7(c *C) {
	identityCache := initIdentityCache()

	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{
									Method:  "GET",
									Path:    "/foo",
									Host:    "foo.cilium.io",
									Headers: []string{"header2 value", "header1"},
								},
							},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
						L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
							HttpRules: &cilium.HttpNetworkPolicyRules{
								HttpRules: []*cilium.HttpNetworkPolicyRule{
									{Headers: []*envoy_api_v2_route.HeaderMatcher{
										{
											Name:  ":authority",
											Value: "foo.cilium.io",
											Regex: &wrappers.BoolValue{Value: true},
										},
										{
											Name:  ":method",
											Value: "GET",
											Regex: &wrappers.BoolValue{Value: true},
										},
										{
											Name:  ":path",
											Value: "/foo",
											Regex: &wrappers.BoolValue{Value: true},
										},
										{
											Name: "header1",
										},
										{
											Name:  "header2",
											Value: "value",
										},
									}},
								},
							},
						},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
						L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
							HttpRules: &cilium.HttpNetworkPolicyRules{
								HttpRules: []*cilium.HttpNetworkPolicyRule{
									{Headers: []*envoy_api_v2_route.HeaderMatcher{
										{
											Name:  ":authority",
											Value: "foo.cilium.io",
											Regex: &wrappers.BoolValue{Value: true},
										},
										{
											Name:  ":method",
											Value: "GET",
											Regex: &wrappers.BoolValue{Value: true},
										},
										{
											Name:  ":path",
											Value: "/foo",
											Regex: &wrappers.BoolValue{Value: true},
										},
										{
											Name: "header1",
										},
										{
											Name:  "header2",
											Value: "value",
										},
									}},
								},
							},
						},
					},
				},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{
									Path:    "/foo",
									Method:  "GET",
									Host:    "foo.cilium.io",
									Headers: []string{"header2 value", "header1"},
								},
								{
									Path:   "/bar",
									Method: "PUT",
								},
							},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
						L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
							HttpRules: &cilium.HttpNetworkPolicyRules{
								HttpRules: []*cilium.HttpNetworkPolicyRule{
									{
										Headers: []*envoy_api_v2_route.HeaderMatcher{
											{
												Name:  ":method",
												Value: "PUT",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":path",
												Value: "/bar",
												Regex: &wrappers.BoolValue{Value: true},
											},
										},
									},
									{
										Headers: []*envoy_api_v2_route.HeaderMatcher{
											{
												Name:  ":authority",
												Value: "foo.cilium.io",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":method",
												Value: "GET",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":path",
												Value: "/foo",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name: "header1",
											},
											{
												Name:  "header2",
												Value: "value",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
						L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
							HttpRules: &cilium.HttpNetworkPolicyRules{
								HttpRules: []*cilium.HttpNetworkPolicyRule{
									{
										Headers: []*envoy_api_v2_route.HeaderMatcher{
											{
												Name:  ":method",
												Value: "PUT",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":path",
												Value: "/bar",
												Regex: &wrappers.BoolValue{Value: true},
											},
										},
									},
									{
										Headers: []*envoy_api_v2_route.HeaderMatcher{
											{
												Name:  ":authority",
												Value: "foo.cilium.io",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":method",
												Value: "GET",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":path",
												Value: "/foo",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name: "header1",
											},
											{
												Name:  "header2",
												Value: "value",
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
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	// Basic egress test which includes rules at L7.
	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Egress: []api.EgressRule{
				{
					ToEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{
									Method:  "GET",
									Path:    "/foo",
									Host:    "foo.cilium.io",
									Headers: []string{"header2 value", "header1"},
								},
							},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
						L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
							HttpRules: &cilium.HttpNetworkPolicyRules{
								HttpRules: []*cilium.HttpNetworkPolicyRule{
									{Headers: []*envoy_api_v2_route.HeaderMatcher{
										{
											Name:  ":authority",
											Value: "foo.cilium.io",
											Regex: &wrappers.BoolValue{Value: true},
										},
										{
											Name:  ":method",
											Value: "GET",
											Regex: &wrappers.BoolValue{Value: true},
										},
										{
											Name:  ":path",
											Value: "/foo",
											Regex: &wrappers.BoolValue{Value: true},
										},
										{
											Name: "header1",
										},
										{
											Name:  "header2",
											Value: "value",
										},
									}},
								},
							},
						},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
						L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
							HttpRules: &cilium.HttpNetworkPolicyRules{
								HttpRules: []*cilium.HttpNetworkPolicyRule{
									{Headers: []*envoy_api_v2_route.HeaderMatcher{
										{
											Name:  ":authority",
											Value: "foo.cilium.io",
											Regex: &wrappers.BoolValue{Value: true},
										},
										{
											Name:  ":method",
											Value: "GET",
											Regex: &wrappers.BoolValue{Value: true},
										},
										{
											Name:  ":path",
											Value: "/foo",
											Regex: &wrappers.BoolValue{Value: true},
										},
										{
											Name: "header1",
										},
										{
											Name:  "header2",
											Value: "value",
										},
									}},
								},
							},
						},
					},
				},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Egress: []api.EgressRule{
				{
					ToEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{
									Path:    "/foo",
									Method:  "GET",
									Host:    "foo.cilium.io",
									Headers: []string{"header2 value", "header1"},
								},
								{
									Path:   "/bar",
									Method: "PUT",
								},
							},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
						L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
							HttpRules: &cilium.HttpNetworkPolicyRules{
								HttpRules: []*cilium.HttpNetworkPolicyRule{
									{
										Headers: []*envoy_api_v2_route.HeaderMatcher{
											{
												Name:  ":method",
												Value: "PUT",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":path",
												Value: "/bar",
												Regex: &wrappers.BoolValue{Value: true},
											},
										},
									},
									{
										Headers: []*envoy_api_v2_route.HeaderMatcher{
											{
												Name:  ":authority",
												Value: "foo.cilium.io",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":method",
												Value: "GET",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":path",
												Value: "/foo",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name: "header1",
											},
											{
												Name:  "header2",
												Value: "value",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
						L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
							HttpRules: &cilium.HttpNetworkPolicyRules{
								HttpRules: []*cilium.HttpNetworkPolicyRule{
									{
										Headers: []*envoy_api_v2_route.HeaderMatcher{
											{
												Name:  ":method",
												Value: "PUT",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":path",
												Value: "/bar",
												Regex: &wrappers.BoolValue{Value: true},
											},
										},
									},
									{
										Headers: []*envoy_api_v2_route.HeaderMatcher{
											{
												Name:  ":authority",
												Value: "foo.cilium.io",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":method",
												Value: "GET",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":path",
												Value: "/foo",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name: "header1",
											},
											{
												Name:  "header2",
												Value: "value",
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
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)
}

func (ds *ResolverTestSuite) TestResolveL3L4WithRequirements(c *C) {
	identityCache := initIdentityCache()

	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromRequires: []api.EndpointSelector{
						api.NewESFromLabels(durantLabel),
					},
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)

	// Since the rule had FromRequires, we only allow to identityWarriors,
	// which has labelDurant. If we didn't have FromRequires, we'd also have
	// identitySplashBros, and identitySteph, as an allowed RemotePolicy on Port 80.
	// Duplicate IngressPerPortPolicies are generated because we do not
	// coalesce at this stage.
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	// Test that when all L3 is allowed, but FromRequires is used, that not all
	// remote policies are allowed. This is because FromRequires restricts
	// the set of identities which are evaluated for policy.
	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromRequires: []api.EndpointSelector{
						api.NewESFromLabels(stephLabel),
					},
					FromEndpoints: []api.EndpointSelector{
						api.WildcardEndpointSelector,
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)

	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identity30)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	// Same test but with egress.

	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Egress: []api.EgressRule{
				{
					ToRequires: []api.EndpointSelector{
						api.NewESFromLabels(durantLabel),
					},
					ToEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					ToEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)

	// Since the rule had ToRequires, we only allow to identityWarriors,
	// which has labelDurant. If we didn't have FromRequires, we'd also have
	// identitySplashBros, and identitySteph, as an allowed RemotePolicy on Port 80.
	// Duplicate EgressPerPortPolicies are generated because we do not
	// coalesce at this stage.
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)
}

func (ds *ResolverTestSuite) TestResolveL3L4WithRequirementsNoEndpointSelector(c *C) {
	identityCache := initIdentityCache()

	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromRequires: []api.EndpointSelector{
						api.NewESFromLabels(durantLabel),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)

	// Since the rule had FromRequires, we only allow to identity35, and
	// identityWarriors, which has labelDurant. If we didn't have FromRequires,
	// we'd allow all identities. Duplicate rules for port 80 allowing for
	// identityWarriors are expected vecause we do not coalesce at this stage.
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identity35)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)
}

// Ensure that no L7 rules are generated for anything with protocol UDP.
func (ds *ResolverTestSuite) TestNoUDPL7RulesGenerated(c *C) {
	identityCache := initIdentityCache()

	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						endpointSelectorSplashBros,
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoAny},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{
									Path:    "/foo",
									Method:  "GET",
									Host:    "foo.cilium.io",
									Headers: []string{"header2 value", "header1"},
								},
								{
									Path:   "/bar",
									Method: "PUT",
								},
							},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
						L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
							HttpRules: &cilium.HttpNetworkPolicyRules{
								HttpRules: []*cilium.HttpNetworkPolicyRule{
									{
										Headers: []*envoy_api_v2_route.HeaderMatcher{
											{
												Name:  ":method",
												Value: "PUT",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":path",
												Value: "/bar",
												Regex: &wrappers.BoolValue{Value: true},
											},
										},
									},
									{
										Headers: []*envoy_api_v2_route.HeaderMatcher{
											{
												Name:  ":authority",
												Value: "foo.cilium.io",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":method",
												Value: "GET",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":path",
												Value: "/foo",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name: "header1",
											},
											{
												Name:  "header2",
												Value: "value",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
						L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
							HttpRules: &cilium.HttpNetworkPolicyRules{
								HttpRules: []*cilium.HttpNetworkPolicyRule{
									{
										Headers: []*envoy_api_v2_route.HeaderMatcher{
											{
												Name:  ":method",
												Value: "PUT",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":path",
												Value: "/bar",
												Regex: &wrappers.BoolValue{Value: true},
											},
										},
									},
									{
										Headers: []*envoy_api_v2_route.HeaderMatcher{
											{
												Name:  ":authority",
												Value: "foo.cilium.io",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":method",
												Value: "GET",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":path",
												Value: "/foo",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name: "header1",
											},
											{
												Name:  "header2",
												Value: "value",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_UDP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_UDP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

}
