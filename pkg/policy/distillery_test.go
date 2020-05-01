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

package policy

import (
	"bytes"
	"fmt"
	"io"
	stdlog "log"
	"testing"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/testutils"

	. "gopkg.in/check.v1"
)

//
// Distillery unit tests
//

type DistilleryTestSuite struct{}

var (
	_ = Suite(&DistilleryTestSuite{})

	ep1 = testutils.NewTestEndpoint()
	ep2 = testutils.NewTestEndpoint()
)

func (s *DistilleryTestSuite) TestCacheManagement(c *C) {
	repo := NewPolicyRepository(nil, nil)
	cache := repo.policyCache
	identity := ep1.GetSecurityIdentity()
	c.Assert(ep2.GetSecurityIdentity(), Equals, identity)

	// Nonsense delete of entry that isn't yet inserted
	deleted := cache.delete(identity)
	c.Assert(deleted, Equals, false)

	// Insert identity twice. Should be the same policy.
	policy1, _ := cache.insert(identity)
	policy2, _ := cache.insert(identity)
	c.Assert(policy1, Equals, policy2)

	// Despite two insert calls, there is no reference tracking; any delete
	// will clear the cache.
	cacheCleared := cache.delete(identity)
	c.Assert(cacheCleared, Equals, true)
	cacheCleared = cache.delete(identity)
	c.Assert(cacheCleared, Equals, false)

	// Insert two distinct identities, then delete one. Other should still
	// be there.
	ep3 := testutils.NewTestEndpoint()
	ep3.SetIdentity(1234, true)
	identity3 := ep3.GetSecurityIdentity()
	c.Assert(identity3, Not(Equals), identity)
	policy1, _ = cache.insert(identity)
	policy3, _ := cache.insert(identity3)
	c.Assert(policy1, Not(Equals), policy3)
	_ = cache.delete(identity)
	policy3, _ = cache.lookupOrCreate(identity3, false)
	c.Assert(policy3, NotNil)
}

func (s *DistilleryTestSuite) TestCachePopulation(c *C) {
	repo := NewPolicyRepository(nil, nil)
	repo.revision = 42
	cache := repo.policyCache

	identity1 := ep1.GetSecurityIdentity()
	c.Assert(ep2.GetSecurityIdentity(), Equals, identity1)
	policy1, computed := cache.insert(identity1)
	c.Assert(computed, Equals, false)

	// Calculate the policy and observe that it's cached
	updated, err := cache.updateSelectorPolicy(identity1)
	c.Assert(err, IsNil)
	c.Assert(updated, Equals, true)
	updated, err = cache.updateSelectorPolicy(identity1)
	c.Assert(err, IsNil)
	c.Assert(updated, Equals, false)
	policy2, computed := cache.insert(identity1)
	c.Assert(computed, Equals, true)
	idp1 := policy1.(*cachedSelectorPolicy).getPolicy()
	idp2 := policy2.(*cachedSelectorPolicy).getPolicy()
	c.Assert(idp1, Equals, idp2)

	// Remove the identity and observe that it is no longer available
	cacheCleared := cache.delete(identity1)
	c.Assert(cacheCleared, Equals, true)
	updated, err = cache.updateSelectorPolicy(identity1)
	c.Assert(err, NotNil)

	// Attempt to update policy for non-cached endpoint and observe failure
	ep3 := testutils.NewTestEndpoint()
	ep3.SetIdentity(1234, true)
	_, err = cache.updateSelectorPolicy(ep3.GetSecurityIdentity())
	c.Assert(err, NotNil)
	c.Assert(updated, Equals, false)

	// Insert endpoint with different identity and observe that the cache
	// is different from ep1, ep2
	policy1, computed = cache.insert(identity1)
	c.Assert(computed, Equals, false)
	idp1 = policy1.(*cachedSelectorPolicy).getPolicy()
	c.Assert(idp1, NotNil)
	identity3 := ep3.GetSecurityIdentity()
	policy3, computed := cache.insert(identity3)
	c.Assert(policy3, Not(Equals), policy1)
	c.Assert(computed, Equals, false)
	updated, err = cache.updateSelectorPolicy(identity3)
	c.Assert(err, IsNil)
	c.Assert(updated, Equals, true)
	idp3 := policy3.(*cachedSelectorPolicy).getPolicy()
	c.Assert(idp3, Not(Equals), idp1)

	// If there's an error during policy resolution, update should fail
	//repo.err = fmt.Errorf("not implemented!")
	//repo.revision++
	//_, err = cache.updateSelectorPolicy(identity3)
	//c.Assert(err, NotNil)
}

//
// Distillery integration tests
//

var (
	// Identity, labels, selectors for an endpoint named "foo"
	identityFoo = uint32(100)
	labelsFoo   = labels.ParseSelectLabelArray("foo", "red")
	selectFoo_  = api.NewESFromLabels(labels.ParseSelectLabel("foo"))
	allowFooL3_ = selectFoo_

	// Identity, labels, selectors for an endpoint named "bar"
	identityBar = uint32(200)
	labelsBar   = labels.ParseSelectLabelArray("bar", "blue")
	selectBar_  = api.NewESFromLabels(labels.ParseSelectLabel("bar"))
	allowBarL3_ = selectBar_

	// API rule sections for composability
	// L4 rule sections
	allowAllL4_ []api.PortRule
	allowPort80 = []api.PortRule{{
		Ports: []api.PortProtocol{
			{Port: "80", Protocol: api.ProtoTCP},
		},
	}}
	allowNamedPort80 = []api.PortRule{{
		Ports: []api.PortProtocol{
			{Port: "port-80", Protocol: api.ProtoTCP},
		},
	}}
	// L7 rule sections
	allowHTTPRoot = &api.L7Rules{
		HTTP: []api.PortRuleHTTP{
			{Method: "GET", Path: "/"},
		},
		L7Proto: ParserTypeHTTP.String(),
	}
	// API rule definitions for default-deny, L3, L3L4, L3L4L7, L4, L4L7
	lbls____NoAllow = labels.ParseLabelArray("no-allow")
	rule____NoAllow = api.NewRule().
			WithLabels(lbls____NoAllow).
			WithIngressRules([]api.IngressRule{{}})
	lblsL3____Allow = labels.ParseLabelArray("l3-allow")
	ruleL3____Allow = api.NewRule().
			WithLabels(lblsL3____Allow).
			WithIngressRules([]api.IngressRule{{
			FromEndpoints: []api.EndpointSelector{allowFooL3_},
			ToPorts:       allowAllL4_,
		}})
	lblsL3L4__Allow = labels.ParseLabelArray("l3l4-allow")
	ruleL3L4__Allow = api.NewRule().
			WithLabels(lblsL3L4__Allow).
			WithIngressRules([]api.IngressRule{{
			FromEndpoints: []api.EndpointSelector{allowFooL3_},
			ToPorts:       allowPort80,
		}})
	ruleL3npL4__Allow = api.NewRule().
				WithLabels(lblsL3L4__Allow).
				WithIngressRules([]api.IngressRule{{
			FromEndpoints: []api.EndpointSelector{allowFooL3_},
			ToPorts:       allowNamedPort80,
		}})
	lblsL3L4L7Allow = labels.ParseLabelArray("l3l4l7-allow")
	ruleL3L4L7Allow = api.NewRule().
			WithLabels(lblsL3L4L7Allow).
			WithIngressRules([]api.IngressRule{{
			FromEndpoints: []api.EndpointSelector{allowFooL3_},
			ToPorts:       combineL4L7(allowPort80, allowHTTPRoot),
		}})
	ruleL3npL4L7Allow = api.NewRule().
				WithLabels(lblsL3L4L7Allow).
				WithIngressRules([]api.IngressRule{{
			FromEndpoints: []api.EndpointSelector{allowFooL3_},
			ToPorts:       combineL4L7(allowNamedPort80, allowHTTPRoot),
		}})
	lbls__L4__Allow = labels.ParseLabelArray("l4-allow")
	rule__L4__Allow = api.NewRule().
			WithLabels(lbls__L4__Allow).
			WithIngressRules([]api.IngressRule{{
			ToPorts: allowPort80,
		}})
	rule__npL4__Allow = api.NewRule().
				WithLabels(lbls__L4__Allow).
				WithIngressRules([]api.IngressRule{{
			ToPorts: allowNamedPort80,
		}})
	lbls__L4L7Allow = labels.ParseLabelArray("l4l7-allow")
	rule__L4L7Allow = api.NewRule().
			WithLabels(lbls__L4L7Allow).
			WithIngressRules([]api.IngressRule{{
			ToPorts: combineL4L7(allowPort80, allowHTTPRoot),
		}})
	rule__npL4L7Allow = api.NewRule().
				WithLabels(lbls__L4L7Allow).
				WithIngressRules([]api.IngressRule{{
			ToPorts: combineL4L7(allowNamedPort80, allowHTTPRoot),
		}})
	lbls__L3AllowFoo = labels.ParseLabelArray("l3-allow-foo")
	rule__L3AllowFoo = api.NewRule().
				WithLabels(lbls__L3AllowFoo).
				WithIngressRules([]api.IngressRule{{
			FromEndpoints: []api.EndpointSelector{allowFooL3_},
		}})
	lbls__L3AllowBar = labels.ParseLabelArray("l3-allow-bar")
	rule__L3AllowBar = api.NewRule().
				WithLabels(lbls__L3AllowBar).
				WithIngressRules([]api.IngressRule{{
			FromEndpoints: []api.EndpointSelector{allowBarL3_},
		}})
	lbls____AllowAll = labels.ParseLabelArray("allow-all")
	rule____AllowAll = api.NewRule().
				WithLabels(lbls____AllowAll).
				WithIngressRules([]api.IngressRule{{
			FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
		}})
	lblsAllowLocalHostIngress = labels.LabelArray{
		labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowLocalHostIngress, labels.LabelSourceReserved),
	}

	// Misc other bpf key fields for convenience / readability.
	l7RedirectNone_ = uint16(0)
	l7RedirectProxy = uint16(1)
	dirIngress      = trafficdirection.Ingress.Uint8()
	// Desired map keys for L3, L3-dependent L4, L4
	mapKeyAllowFoo__ = Key{identityFoo, 0, 0, dirIngress}
	mapKeyAllowBar__ = Key{identityBar, 0, 0, dirIngress}
	mapKeyAllowFooL4 = Key{identityFoo, 80, 6, dirIngress}
	mapKeyAllow___L4 = Key{0, 80, 6, dirIngress}
	mapKeyAllowAll__ = Key{0, 0, 0, dirIngress}
	// Desired map entries for no L7 redirect / redirect to Proxy
	mapEntryL7None_ = func(lbls ...labels.LabelArray) MapStateEntry {
		return NewMapStateEntry(labels.LabelArrayList(lbls).Sort(), false)
	}
	mapEntryL7Proxy = func(lbls ...labels.LabelArray) MapStateEntry {
		return NewMapStateEntry(labels.LabelArrayList(lbls).Sort(), true)
	}
)

// combineL4L7 returns a new PortRule that refers to the specified l4 ports and
// l7 rules.
func combineL4L7(l4 []api.PortRule, l7 *api.L7Rules) []api.PortRule {
	result := make([]api.PortRule, 0, len(l4))
	for _, pr := range l4 {
		result = append(result, api.PortRule{
			Ports: pr.Ports,
			Rules: l7,
		})
	}
	return result
}

// policyDistillery is a convenience wrapper around the existing policy engine,
// allowing simple direct evaluation of L3 and L4 state into "MapState".
type policyDistillery struct {
	*Repository
	log io.Writer
}

func newPolicyDistillery(selectorCache *SelectorCache) *policyDistillery {
	ret := &policyDistillery{
		Repository: NewPolicyRepository(nil, nil),
	}
	ret.selectorCache = selectorCache
	return ret
}

func (d *policyDistillery) WithLogBuffer(w io.Writer) *policyDistillery {
	return &policyDistillery{
		Repository: d.Repository,
		log:        w,
	}
}

// distillPolicy distills the policy repository into a set of bpf map state
// entries for an endpoint with the specified labels.
func (d *policyDistillery) distillPolicy(npMap NamedPortsMap, epLabels labels.LabelArray) (MapState, error) {
	result := make(MapState)

	endpointSelected, _ := d.Repository.GetRulesMatching(epLabels)
	io.WriteString(d.log, fmt.Sprintf("[distill] Endpoint selected by policy: %t\n", endpointSelected))
	if !endpointSelected {
		allowAllIngress := true
		allowAllEgress := false // Skip egress
		result.AllowAllIdentities(allowAllIngress, allowAllEgress)
		return result, nil
	}

	// Prepare the L4 policy so we know whether L4 policy may apply
	ingressL4 := SearchContext{
		To:    epLabels,
		Trace: TRACE_VERBOSE,
	}
	ingressL4.Logging = stdlog.New(d.log, "", 0)
	io.WriteString(d.log, fmt.Sprintf("[distill] Evaluating L4 -> %s", epLabels))
	l4IngressPolicy, err := d.Repository.ResolveL4IngressPolicy(&ingressL4)
	if err != nil {
		return nil, err
	}

	// Handle L4 ingress from each identity in the cache to the endpoint.
	io.WriteString(d.log, "[distill] Producing L4 filter keys\n")
	for _, l4 := range l4IngressPolicy {
		io.WriteString(d.log, fmt.Sprintf("[distill] Processing L4Filter (l4: %d/%s), (l3/7: %+v)\n", l4.Port, l4.Protocol, l4.L7RulesPerSelector))
		for key, entry := range l4.ToMapState(npMap, 0) {
			io.WriteString(d.log, fmt.Sprintf("[distill] L4 ingress allow %+v (parser=%s, redirect=%t)\n", key, l4.L7Parser, entry.IsRedirectEntry()))
			result[key] = entry
		}
	}
	l4IngressPolicy.Detach(d.Repository.GetSelectorCache())
	return result, nil
}

func Test_MergeL3(t *testing.T) {
	identityCache := cache.IdentityCache{
		identity.NumericIdentity(identityFoo): labelsFoo,
		identity.NumericIdentity(identityBar): labelsBar,
	}
	selectorCache := testNewSelectorCache(identityCache)

	tests := []struct {
		test   int
		rules  api.Rules
		result MapState
	}{
		{0, api.Rules{rule__L3AllowFoo, rule__L3AllowBar}, MapState{mapKeyAllowFoo__: mapEntryL7None_(lbls__L3AllowFoo, lbls__L3AllowBar), mapKeyAllowBar__: mapEntryL7None_(lbls__L3AllowFoo, lbls__L3AllowBar)}},
		{1, api.Rules{rule__L3AllowFoo, ruleL3L4__Allow}, MapState{mapKeyAllowFoo__: mapEntryL7None_(lbls__L3AllowFoo), mapKeyAllowFooL4: mapEntryL7None_(lblsL3L4__Allow)}},
	}

	for _, tt := range tests {
		repo := newPolicyDistillery(selectorCache)
		for _, r := range tt.rules {
			if r != nil {
				rule := r.WithEndpointSelector(selectFoo_)
				_, _ = repo.AddList(api.Rules{rule})
			}
		}
		t.Run(fmt.Sprintf("permutation_%d", tt.test), func(t *testing.T) {
			logBuffer := new(bytes.Buffer)
			repo = repo.WithLogBuffer(logBuffer)
			mapstate, err := repo.distillPolicy(nil, labelsFoo)
			if err != nil {
				t.Errorf("Policy resolution failure: %s", err)
			}
			if equal, err := checker.DeepEqual(mapstate, tt.result); !equal {
				t.Logf("Rules:\n%s\n\n", tt.rules.String())
				t.Logf("Policy Trace: \n%s\n", logBuffer.String())
				t.Errorf("Policy obtained didn't match expected for endpoint %s:\n%s", labelsFoo, err)
			}
		})
	}
}

func Test_MergeRules(t *testing.T) {
	identityCache := cache.IdentityCache{
		identity.NumericIdentity(identityFoo): labelsFoo,
	}
	selectorCache := testNewSelectorCache(identityCache)

	tests := []struct {
		test   int
		rules  api.Rules
		result MapState
	}{
		// The following table is derived from the Google Doc here:
		// https://docs.google.com/spreadsheets/d/1WANIoZGB48nryylQjjOw6lKjI80eVgPShrdMTMalLEw/edit?usp=sharing
		//
		//  Rule 0                   | Rule 1         | Rule 2         | Rule 3         | Rule 4         | Desired BPF map state
		{0, api.Rules{rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, MapState{}},
		{1, api.Rules{rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},
		{2, api.Rules{rule____NoAllow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow)}},
		{3, api.Rules{rule____NoAllow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},
		{4, api.Rules{rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7None_(lblsL3L4__Allow)}},
		{5, api.Rules{rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7None_(lblsL3L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},
		{6, api.Rules{rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7None_(lblsL3L4__Allow, lbls__L4__Allow)}},                                                     // identical L3L4 entry suppressed
		{7, api.Rules{rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7None_(lblsL3L4__Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}}, // identical L3L4 entry suppressed
		{8, api.Rules{rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow)}},
		{9, api.Rules{rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},
		{10, api.Rules{rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow)}},
		{11, api.Rules{rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},
		{12, api.Rules{rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lblsL3L4__Allow)}},                                                                      // L3L4 entry suppressed to allow L4-only entry to redirect
		{13, api.Rules{rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lblsL3L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},                  // L3L4 entry suppressed to allow L4-only entry to redirect
		{14, api.Rules{rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lblsL3L4__Allow, lbls__L4__Allow)}},                                                     // L3L4 entry suppressed to allow L4-only entry to redirect
		{15, api.Rules{rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lblsL3L4__Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}}, // L3L4 entry suppressed to allow L4-only entry to redirect
		{16, api.Rules{ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow)}},
		{17, api.Rules{ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},
		{18, api.Rules{ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4__Allow), mapKeyAllow___L4: mapEntryL7None_(lblsL3L4L7Allow, lbls__L4__Allow)}},
		{19, api.Rules{ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4__Allow), mapKeyAllow___L4: mapEntryL7None_(lblsL3L4L7Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},
		{20, api.Rules{ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lblsL3L4__Allow)}},
		{21, api.Rules{ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lblsL3L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},
		{22, api.Rules{ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lblsL3L4__Allow, lbls__L4__Allow), mapKeyAllow___L4: mapEntryL7None_(lblsL3L4L7Allow, lblsL3L4__Allow, lbls__L4__Allow)}},
		{23, api.Rules{ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lblsL3L4__Allow, lbls__L4__Allow), mapKeyAllow___L4: mapEntryL7None_(lblsL3L4L7Allow, lblsL3L4__Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},
		{24, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4L7Allow)}},                                                                                       // identical L3L4 entry suppressed
		{25, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},                                   // identical L3L4 entry suppressed
		{26, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4L7Allow, lbls__L4__Allow)}},                                                                      // identical L3L4 entry suppressed
		{27, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4L7Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},                  // identical L3L4 entry suppressed
		{28, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4L7Allow, lblsL3L4__Allow)}},                                                                      // identical L3L4 entry suppressed
		{29, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4L7Allow, lblsL3L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},                  // identical L3L4 entry suppressed
		{30, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4L7Allow, lblsL3L4__Allow, lbls__L4__Allow)}},                                                     // identical L3L4 entry suppressed
		{31, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4L7Allow, lblsL3L4__Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}}, // identical L3L4 entry suppressed
	}
	for _, tt := range tests {
		repo := newPolicyDistillery(selectorCache)
		for _, r := range tt.rules {
			if r != nil {
				rule := r.WithEndpointSelector(selectFoo_)
				_, _ = repo.AddList(api.Rules{rule})
			}
		}
		t.Run(fmt.Sprintf("permutation_%d", tt.test), func(t *testing.T) {
			logBuffer := new(bytes.Buffer)
			repo = repo.WithLogBuffer(logBuffer)
			mapstate, err := repo.distillPolicy(nil, labelsFoo)
			if err != nil {
				t.Errorf("Policy resolution failure: %s", err)
			}
			if equal, err := checker.DeepEqual(mapstate, tt.result); !equal {
				t.Logf("Rules:\n%s\n\n", tt.rules.String())
				t.Logf("Policy Trace: \n%s\n", logBuffer.String())
				t.Errorf("Policy obtained didn't match expected for endpoint %s:\n%s", labelsFoo, err)
			}
		})
	}
}

func Test_MergeRulesWithNamedPorts(t *testing.T) {
	identityCache := cache.IdentityCache{
		identity.NumericIdentity(identityFoo): labelsFoo,
	}
	selectorCache := testNewSelectorCache(identityCache)

	npMap := NamedPortsMap{
		"port-80": NamedPort{Proto: uint8(0), Port: uint16(80)},
	}

	tests := []struct {
		test   int
		rules  api.Rules
		result MapState
	}{
		// The following table is derived from the Google Doc here:
		// https://docs.google.com/spreadsheets/d/1WANIoZGB48nryylQjjOw6lKjI80eVgPShrdMTMalLEw/edit?usp=sharing
		//
		//  Rule 0                   | Rule 1         | Rule 2         | Rule 3         | Rule 4         | Desired BPF map state
		{0, api.Rules{rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, MapState{}},
		{1, api.Rules{rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},
		{2, api.Rules{rule____NoAllow, rule____NoAllow, rule____NoAllow, rule__npL4__Allow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow)}},
		{3, api.Rules{rule____NoAllow, rule____NoAllow, rule____NoAllow, rule__npL4__Allow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},
		{4, api.Rules{rule____NoAllow, rule____NoAllow, ruleL3npL4__Allow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7None_(lblsL3L4__Allow)}},
		{5, api.Rules{rule____NoAllow, rule____NoAllow, ruleL3npL4__Allow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7None_(lblsL3L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},
		{6, api.Rules{rule____NoAllow, rule____NoAllow, ruleL3npL4__Allow, rule__npL4__Allow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7None_(lblsL3L4__Allow, lbls__L4__Allow)}},                                                     // identical L3L4 entry suppressed
		{7, api.Rules{rule____NoAllow, rule____NoAllow, ruleL3npL4__Allow, rule__npL4__Allow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7None_(lblsL3L4__Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}}, // identical L3L4 entry suppressed
		{8, api.Rules{rule____NoAllow, rule__npL4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow)}},
		{9, api.Rules{rule____NoAllow, rule__npL4L7Allow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},
		{10, api.Rules{rule____NoAllow, rule__npL4L7Allow, rule____NoAllow, rule__npL4__Allow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow)}},
		{11, api.Rules{rule____NoAllow, rule__npL4L7Allow, rule____NoAllow, rule__npL4__Allow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},
		{12, api.Rules{rule____NoAllow, rule__npL4L7Allow, ruleL3npL4__Allow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lblsL3L4__Allow)}},                                                                        // L3L4 entry suppressed to allow L4-only entry to redirect
		{13, api.Rules{rule____NoAllow, rule__npL4L7Allow, ruleL3npL4__Allow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lblsL3L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},                    // L3L4 entry suppressed to allow L4-only entry to redirect
		{14, api.Rules{rule____NoAllow, rule__npL4L7Allow, ruleL3npL4__Allow, rule__npL4__Allow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lblsL3L4__Allow, lbls__L4__Allow)}},                                                     // L3L4 entry suppressed to allow L4-only entry to redirect
		{15, api.Rules{rule____NoAllow, rule__npL4L7Allow, ruleL3npL4__Allow, rule__npL4__Allow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lblsL3L4__Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}}, // L3L4 entry suppressed to allow L4-only entry to redirect
		{16, api.Rules{ruleL3npL4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow)}},
		{17, api.Rules{ruleL3npL4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},
		{18, api.Rules{ruleL3npL4L7Allow, rule____NoAllow, rule____NoAllow, rule__npL4__Allow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4__Allow), mapKeyAllow___L4: mapEntryL7None_(lblsL3L4L7Allow, lbls__L4__Allow)}},
		{19, api.Rules{ruleL3npL4L7Allow, rule____NoAllow, rule____NoAllow, rule__npL4__Allow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4__Allow), mapKeyAllow___L4: mapEntryL7None_(lblsL3L4L7Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},
		{20, api.Rules{ruleL3npL4L7Allow, rule____NoAllow, ruleL3npL4__Allow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lblsL3L4__Allow)}},
		{21, api.Rules{ruleL3npL4L7Allow, rule____NoAllow, ruleL3npL4__Allow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lblsL3L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},
		{22, api.Rules{ruleL3npL4L7Allow, rule____NoAllow, ruleL3npL4__Allow, rule__npL4__Allow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lblsL3L4__Allow, lbls__L4__Allow), mapKeyAllow___L4: mapEntryL7None_(lblsL3L4L7Allow, lblsL3L4__Allow, lbls__L4__Allow)}},
		{23, api.Rules{ruleL3npL4L7Allow, rule____NoAllow, ruleL3npL4__Allow, rule__npL4__Allow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lblsL3L4__Allow, lbls__L4__Allow), mapKeyAllow___L4: mapEntryL7None_(lblsL3L4L7Allow, lblsL3L4__Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},
		{24, api.Rules{ruleL3npL4L7Allow, rule__npL4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4L7Allow)}},                                                                                           // identical L3L4 entry suppressed
		{25, api.Rules{ruleL3npL4L7Allow, rule__npL4L7Allow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},                                       // identical L3L4 entry suppressed
		{26, api.Rules{ruleL3npL4L7Allow, rule__npL4L7Allow, rule____NoAllow, rule__npL4__Allow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4L7Allow, lbls__L4__Allow)}},                                                                        // identical L3L4 entry suppressed
		{27, api.Rules{ruleL3npL4L7Allow, rule__npL4L7Allow, rule____NoAllow, rule__npL4__Allow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4L7Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},                    // identical L3L4 entry suppressed
		{28, api.Rules{ruleL3npL4L7Allow, rule__npL4L7Allow, ruleL3npL4__Allow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4L7Allow, lblsL3L4__Allow)}},                                                                        // identical L3L4 entry suppressed
		{29, api.Rules{ruleL3npL4L7Allow, rule__npL4L7Allow, ruleL3npL4__Allow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4L7Allow, lblsL3L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}},                    // identical L3L4 entry suppressed
		{30, api.Rules{ruleL3npL4L7Allow, rule__npL4L7Allow, ruleL3npL4__Allow, rule__npL4__Allow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4L7Allow, lblsL3L4__Allow, lbls__L4__Allow)}},                                                     // identical L3L4 entry suppressed
		{31, api.Rules{ruleL3npL4L7Allow, rule__npL4L7Allow, ruleL3npL4__Allow, rule__npL4__Allow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy(lblsL3L4L7Allow, lbls__L4L7Allow, lblsL3L4__Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)}}, // identical L3L4 entry suppressed
	}
	for _, tt := range tests {
		repo := newPolicyDistillery(selectorCache)
		for _, r := range tt.rules {
			if r != nil {
				rule := r.WithEndpointSelector(selectFoo_)
				_, _ = repo.AddList(api.Rules{rule})
			}
		}
		t.Run(fmt.Sprintf("permutation_%d", tt.test), func(t *testing.T) {
			logBuffer := new(bytes.Buffer)
			repo = repo.WithLogBuffer(logBuffer)
			mapstate, err := repo.distillPolicy(npMap, labelsFoo)
			if err != nil {
				t.Errorf("Policy resolution failure: %s", err)
			}
			if equal, err := checker.DeepEqual(mapstate, tt.result); !equal {
				t.Logf("Rules:\n%s\n\n", tt.rules.String())
				t.Logf("Policy Trace: \n%s\n", logBuffer.String())
				t.Errorf("Policy obtained didn't match expected for endpoint %s:\n%s", labelsFoo, err)
			}
		})
	}
}

func Test_AllowAll(t *testing.T) {
	identityCache := cache.IdentityCache{
		identity.NumericIdentity(identityFoo): labelsFoo,
		identity.NumericIdentity(identityBar): labelsBar,
	}
	selectorCache := testNewSelectorCache(identityCache)

	tests := []struct {
		test     int
		selector api.EndpointSelector
		rules    api.Rules
		result   MapState
	}{
		{0, api.EndpointSelectorNone, api.Rules{rule____AllowAll}, MapState{mapKeyAllowAll__: mapEntryL7None_(lblsAllowLocalHostIngress)}},
		{1, api.WildcardEndpointSelector, api.Rules{rule____AllowAll}, MapState{mapKeyAllowAll__: mapEntryL7None_(lbls____AllowAll)}},
	}

	for _, tt := range tests {
		repo := newPolicyDistillery(selectorCache)
		for _, r := range tt.rules {
			if r != nil {
				rule := r.WithEndpointSelector(tt.selector)
				_, _ = repo.AddList(api.Rules{rule})
			}
		}
		t.Run(fmt.Sprintf("permutation_%d", tt.test), func(t *testing.T) {
			logBuffer := new(bytes.Buffer)
			repo = repo.WithLogBuffer(logBuffer)
			mapstate, err := repo.distillPolicy(nil, labelsFoo)
			if err != nil {
				t.Errorf("Policy resolution failure: %s", err)
			}
			if equal, err := checker.DeepEqual(mapstate, tt.result); !equal {
				t.Logf("Rules:\n%s\n\n", tt.rules.String())
				t.Logf("Policy Trace: \n%s\n", logBuffer.String())
				t.Errorf("Policy obtained didn't match expected for endpoint %s:\n%s", labelsFoo, err)
			}
		})
	}
}
