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

// +build !privileged_tests

package policy

import (
	"fmt"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
)

var (
	fooLabel = labels.NewLabel("k8s:foo", "", "")
	lbls     = labels.Labels{
		"foo": fooLabel,
	}
	lblsArray   = lbls.LabelArray()
	repo        = &Repository{}
	fooIdentity = &identity.Identity{
		ID:         303,
		Labels:     lbls,
		LabelArray: lbls.LabelArray(),
	}
	identityCache = cache.IdentityCache{303: lblsArray}
)

func (ds *PolicyTestSuite) SetUpSuite(c *C) {
	SetPolicyEnabled(option.DefaultEnforcement)
	GenerateNumIdentities(3000)
	repo.AddList(GenerateNumRules(1000))
}

func (ds *PolicyTestSuite) TearDownSuite(c *C) {
	repo = &Repository{}
}

func GenerateNumIdentities(numIdentities int) {
	for i := 0; i < numIdentities; i++ {

		identityLabel := labels.NewLabel(fmt.Sprintf("k8s:foo%d", i), "", "")

		identityLabels := labels.Labels{
			fmt.Sprintf("foo%d", i): identityLabel,
		}

		bumpedIdentity := i + 1000
		numericIdentity := identity.NumericIdentity(bumpedIdentity)

		identityCache[numericIdentity] = identityLabels.LabelArray()
	}
}

func GenerateNumRules(numRules int) api.Rules {
	parseFooLabel := labels.ParseSelectLabel("k8s:foo")
	fooSelector := api.NewESFromLabels(parseFooLabel)
	barSelector := api.NewESFromLabels(labels.ParseSelectLabel("bar"))

	// Change ingRule and rule in the for-loop below to change what type of rules
	// are added into the policy repository.
	ingRule := api.IngressRule{
		FromEndpoints: []api.EndpointSelector{barSelector},
		/*FromRequires:  []api.EndpointSelector{barSelector},
		ToPorts: []api.PortRule{
			{
				Ports: []api.PortProtocol{
					{
						Port:     "8080",
						Protocol: api.ProtoTCP,
					},
				},
			},
		},*/
	}

	var rules api.Rules
	for i := 1; i <= numRules; i++ {

		rule := api.Rule{
			EndpointSelector: fooSelector,
			Ingress:          []api.IngressRule{ingRule},
		}

		rules = append(rules, &rule)
	}
	return rules
}

type DummyOwner struct{}

func (d DummyOwner) LookupRedirectPort(l4 *L4Filter) uint16 {
	return 0
}

func (ds *PolicyTestSuite) BenchmarkRegeneratePolicyRules(c *C) {
	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		repo.ResolvePolicy(1, lblsArray, DummyOwner{}, identityCache)
	}
}

func (ds *PolicyTestSuite) TestL7WithIngressWildcard(c *C) {
	repo := NewPolicyRepository()

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	rule1 := api.Rule{
		EndpointSelector: selFoo,
		Ingress: []api.IngressRule{
			{
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/good"},
						},
					},
				}},
			},
		},
	}

	rule1.Sanitize()
	_, err := repo.Add(rule1)
	c.Assert(err, IsNil)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	identityCache = cache.GetIdentityCache()
	policy, err := repo.ResolvePolicy(10, labels.ParseSelectLabelArray("id=foo"), DummyOwner{}, identityCache)
	c.Assert(err, IsNil)

	expectedEndpointPolicy := EndpointPolicy{
		ID: 10,
		L4Policy: &L4Policy{
			Ingress: L4PolicyMap{
				"80/TCP": {
					Port:     80,
					Protocol: api.ProtoTCP,
					U8Proto:  0x6,
					Endpoints: []api.EndpointSelector{
						api.WildcardEndpointSelector,
					},
					allowsAllAtL3: true,
					L7Parser:      ParserTypeHTTP,
					Ingress:       true,
					L7RulesPerEp: L7DataMap{
						api.WildcardEndpointSelector: api.L7Rules{
							HTTP: []api.PortRuleHTTP{{Method: "GET", Path: "/good"}},
						},
					},
					DerivedFromRules: labels.LabelArrayList{nil},
				},
			},
			Egress: L4PolicyMap{},
		},
		IngressPolicyEnabled:    true,
		EgressPolicyEnabled:     false,
		PolicyOwner:             DummyOwner{},
		DeniedIngressIdentities: cache.IdentityCache{},
		DeniedEgressIdentities:  cache.IdentityCache{},
		// inherit this from the result as it is outside of the scope
		// of this test
		CIDRPolicy:     policy.CIDRPolicy,
		PolicyMapState: policy.PolicyMapState,
	}

	c.Assert(policy, checker.DeepEquals, &expectedEndpointPolicy)
}

func (ds *PolicyTestSuite) TestL7WithLocalHostWildcardd(c *C) {
	// Emulate Kubernetes mode with allow from localhost
	oldLocalhostOpt := option.Config.AllowLocalhost
	option.Config.AllowLocalhost = option.AllowLocalhostAlways
	defer func() { option.Config.AllowLocalhost = oldLocalhostOpt }()

	repo := NewPolicyRepository()

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	rule1 := api.Rule{
		EndpointSelector: selFoo,
		Ingress: []api.IngressRule{
			{
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/good"},
						},
					},
				}},
			},
		},
	}

	rule1.Sanitize()
	_, err := repo.Add(rule1)
	c.Assert(err, IsNil)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	identityCache = cache.GetIdentityCache()
	policy, err := repo.ResolvePolicy(10, labels.ParseSelectLabelArray("id=foo"), DummyOwner{}, identityCache)
	c.Assert(err, IsNil)

	expectedEndpointPolicy := EndpointPolicy{
		ID: 10,
		L4Policy: &L4Policy{
			Ingress: L4PolicyMap{
				"80/TCP": {
					Port:     80,
					Protocol: api.ProtoTCP,
					U8Proto:  0x6,
					Endpoints: []api.EndpointSelector{
						api.WildcardEndpointSelector,
					},
					allowsAllAtL3: true,
					L7Parser:      ParserTypeHTTP,
					Ingress:       true,
					L7RulesPerEp: L7DataMap{
						api.WildcardEndpointSelector: api.L7Rules{
							HTTP: []api.PortRuleHTTP{{Method: "GET", Path: "/good"}},
						},
						api.ReservedEndpointSelectors[labels.IDNameHost]: api.L7Rules{},
					},
					DerivedFromRules: labels.LabelArrayList{nil},
				},
			},
			Egress: L4PolicyMap{},
		},
		IngressPolicyEnabled:    true,
		EgressPolicyEnabled:     false,
		PolicyOwner:             DummyOwner{},
		DeniedIngressIdentities: cache.IdentityCache{},
		DeniedEgressIdentities:  cache.IdentityCache{},
		// inherit this from the result as it is outside of the scope
		// of this test
		CIDRPolicy:     policy.CIDRPolicy,
		PolicyMapState: policy.PolicyMapState,
	}

	c.Assert(policy, checker.DeepEquals, &expectedEndpointPolicy)
}
