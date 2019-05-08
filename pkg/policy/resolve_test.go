// Copyright 2018-2019 Authors of Cilium
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
	"sync"

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
	fooEndpointId = 9001
)

type dummyEndpoint struct {
	ID               uint16
	SecurityIdentity *identity.Identity
}

func (d *dummyEndpoint) GetID16() uint16 {
	return d.ID
}

func (d *dummyEndpoint) GetSecurityIdentity() *identity.Identity {
	return d.SecurityIdentity
}

func (d *dummyEndpoint) PolicyRevisionBumpEvent(rev uint64) {
	return
}

func (d *dummyEndpoint) RLockAlive() error {
	return nil
}

func (d *dummyEndpoint) RUnlock() {
	return
}

func (ds *PolicyTestSuite) SetUpSuite(c *C) {
	var wg sync.WaitGroup
	SetPolicyEnabled(option.DefaultEnforcement)
	GenerateNumIdentities(3000)
	testSelectorCache.UpdateIdentities(identityCache, nil)
	repo.SelectorCache = testSelectorCache
	rulez, _ := repo.AddList(GenerateNumRules(1000))

	epSet := NewEndpointSet(5)

	epSet.Insert(&dummyEndpoint{
		ID:               9001,
		SecurityIdentity: fooIdentity,
	})
	idSet := NewIDSet()
	rulez.UpdateRulesEndpointsCaches(epSet, idSet, &wg)
	wg.Wait()

	c.Assert(epSet.Len(), Equals, 0)
	c.Assert(len(idSet.IDs), Equals, 1)
}

func (ds *PolicyTestSuite) TearDownSuite(c *C) {
	repo = &Repository{}
}

func GenerateNumIdentities(numIdentities int) {
	for i := 0; i < numIdentities; i++ {

		identityLabel := labels.NewLabel(fmt.Sprintf("k8s:foo%d", i), "", "")
		clusterLabel := labels.NewLabel("io.cilium.k8s.policy.cluster=default", "", labels.LabelSourceK8s)
		serviceAccountLabel := labels.NewLabel("io.cilium.k8s.policy.serviceaccount=default", "", labels.LabelSourceK8s)
		namespaceLabel := labels.NewLabel("io.kubernetes.pod.namespace=monitoring", "", labels.LabelSourceK8s)
		funLabel := labels.NewLabel("app=analytics-erneh", "", labels.LabelSourceK8s)

		identityLabels := labels.Labels{
			fmt.Sprintf("foo%d", i):                           identityLabel,
			"k8s:io.cilium.k8s.policy.cluster=default":        clusterLabel,
			"k8s:io.cilium.k8s.policy.serviceaccount=default": serviceAccountLabel,
			"k8s:io.kubernetes.pod.namespace=monitoring":      namespaceLabel,
			"k8s:app=analytics-erneh":                         funLabel,
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
		rule.Sanitize()
		rules = append(rules, &rule)
	}
	return rules
}

type DummyOwner struct{}

func (d DummyOwner) LookupRedirectPort(l4 *L4Filter) uint16 {
	return 0
}

func (d DummyOwner) GetSecurityIdentity() *identity.Identity {
	return fooIdentity
}

func (ds *PolicyTestSuite) BenchmarkRegeneratePolicyRules(c *C) {
	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		ip, _ := repo.ResolvePolicyLocked(fooIdentity)
		_ = ip.DistillPolicy(DummyOwner{}, testSelectorCache)
	}
}

func (ds *PolicyTestSuite) TestL7WithIngressWildcard(c *C) {

	idFooSelectLabelArray := labels.ParseSelectLabelArray("id=foo")
	idFooSelectLabels := labels.Labels{}
	for _, lbl := range idFooSelectLabelArray {
		idFooSelectLabels[lbl.Key] = lbl
	}
	fooIdentity := identity.NewIdentity(12345, idFooSelectLabels)

	repo := NewPolicyRepository()
	repo.SelectorCache = testSelectorCache

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
	_, _, err := repo.Add(rule1, []Endpoint{})
	c.Assert(err, IsNil)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()
	identityPolicy, err := repo.ResolvePolicyLocked(fooIdentity)
	c.Assert(err, IsNil)
	policy := identityPolicy.DistillPolicy(DummyOwner{}, testSelectorCache)

	expectedEndpointPolicy := EndpointPolicy{
		SelectorPolicy: &SelectorPolicy{
			Revision: repo.GetRevision(),
			L4Policy: &L4Policy{
				Ingress: L4PolicyMap{
					"80/TCP": {
						Port:     80,
						Protocol: api.ProtoTCP,
						U8Proto:  0x6,
						CachedSelectors: CachedSelectorSlice{
							wildcardCachedSelector,
						},
						allowsAllAtL3: true,
						L7Parser:      ParserTypeHTTP,
						Ingress:       true,
						L7RulesPerEp: L7DataMap{
							wildcardCachedSelector: api.L7Rules{
								HTTP: []api.PortRuleHTTP{{Method: "GET", Path: "/good"}},
							},
						},
						DerivedFromRules: labels.LabelArrayList{nil},
					},
				},
				Egress: L4PolicyMap{},
			},
			CIDRPolicy:           policy.CIDRPolicy,
			IngressPolicyEnabled: true,
			EgressPolicyEnabled:  false,
		},
		PolicyOwner: DummyOwner{},
		// inherit this from the result as it is outside of the scope
		// of this test
		PolicyMapState: policy.PolicyMapState,
	}

	c.Assert(policy, checker.Equals, &expectedEndpointPolicy)
}

func (ds *PolicyTestSuite) TestL7WithLocalHostWildcardd(c *C) {
	idFooSelectLabelArray := labels.ParseSelectLabelArray("id=foo")
	idFooSelectLabels := labels.Labels{}
	for _, lbl := range idFooSelectLabelArray {
		idFooSelectLabels[lbl.Key] = lbl
	}

	fooIdentity := identity.NewIdentity(12345, idFooSelectLabels)

	// Emulate Kubernetes mode with allow from localhost
	oldLocalhostOpt := option.Config.AllowLocalhost
	option.Config.AllowLocalhost = option.AllowLocalhostAlways
	defer func() { option.Config.AllowLocalhost = oldLocalhostOpt }()

	repo := NewPolicyRepository()
	repo.SelectorCache = testSelectorCache

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
	_, _, err := repo.Add(rule1, []Endpoint{})
	c.Assert(err, IsNil)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	identityPolicy, err := repo.ResolvePolicyLocked(fooIdentity)
	c.Assert(err, IsNil)
	policy := identityPolicy.DistillPolicy(DummyOwner{}, testSelectorCache)

	cachedSelectorHost := testSelectorCache.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameHost])
	c.Assert(cachedSelectorHost, Not(IsNil))

	expectedEndpointPolicy := EndpointPolicy{
		SelectorPolicy: &SelectorPolicy{
			Revision: repo.GetRevision(),
			L4Policy: &L4Policy{
				Ingress: L4PolicyMap{
					"80/TCP": {
						Port:     80,
						Protocol: api.ProtoTCP,
						U8Proto:  0x6,
						CachedSelectors: CachedSelectorSlice{
							wildcardCachedSelector,
							cachedSelectorHost,
						},
						allowsAllAtL3: true,
						L7Parser:      ParserTypeHTTP,
						Ingress:       true,
						L7RulesPerEp: L7DataMap{
							wildcardCachedSelector: api.L7Rules{
								HTTP: []api.PortRuleHTTP{{Method: "GET", Path: "/good"}},
							},
							cachedSelectorHost: api.L7Rules{},
						},
						DerivedFromRules: labels.LabelArrayList{nil},
					},
				},
				Egress: L4PolicyMap{},
			},
			CIDRPolicy:           policy.CIDRPolicy,
			IngressPolicyEnabled: true,
			EgressPolicyEnabled:  false,
		},
		PolicyOwner: DummyOwner{},
		// inherit this from the result as it is outside of the scope
		// of this test
		PolicyMapState: policy.PolicyMapState,
	}

	c.Assert(policy, checker.Equals, &expectedEndpointPolicy)
}
