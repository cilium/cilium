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
	"testing"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"

	"github.com/op/go-logging"
)

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
	// L7 rule sections
	allowAllL7___ *api.L7Rules
	allowHTTPRoot = &api.L7Rules{
		HTTP: []api.PortRuleHTTP{
			{Method: "GET", Path: "/"},
		},
		L7Proto: ParserTypeHTTP.String(),
	}
	// API rule definitions for default-deny, L3, L3L4, L3L4L7, L4, L4L7
	rule____NoAllow = api.NewRule().
			WithIngressRules([]api.IngressRule{{}})
	ruleL3____Allow = api.NewRule().
			WithIngressRules([]api.IngressRule{{
			FromEndpoints: []api.EndpointSelector{allowFooL3_},
			ToPorts:       allowAllL4_,
		}})
	ruleL3L4__Allow = api.NewRule().
			WithIngressRules([]api.IngressRule{{
			FromEndpoints: []api.EndpointSelector{allowFooL3_},
			ToPorts:       allowPort80,
		}})
	ruleL3L4L7Allow = api.NewRule().
			WithIngressRules([]api.IngressRule{{
			FromEndpoints: []api.EndpointSelector{allowFooL3_},
			ToPorts:       combineL4L7(allowPort80, allowHTTPRoot),
		}})
	rule__L4__Allow = api.NewRule().
			WithIngressRules([]api.IngressRule{{
			ToPorts: allowPort80,
		}})
	rule__L4L7Allow = api.NewRule().
			WithIngressRules([]api.IngressRule{{
			ToPorts: combineL4L7(allowPort80, allowHTTPRoot),
		}})

	rule__L3AllowFoo = api.NewRule().
				WithIngressRules([]api.IngressRule{{
			FromEndpoints: []api.EndpointSelector{allowFooL3_},
		}})

	rule__L3AllowBar = api.NewRule().
				WithIngressRules([]api.IngressRule{{
			FromEndpoints: []api.EndpointSelector{allowBarL3_},
		}})

	// Misc other bpf key fields for convenience / readability.
	l7RedirectNone_ = uint16(0)
	l7RedirectProxy = uint16(1)
	dirIngress      = trafficdirection.Ingress.Uint8()
	// Desired map keys for L3, L3-dependent L4, L4
	mapKeyAllowFoo__ = Key{identityFoo, 0, 0, dirIngress}
	mapKeyAllowBar__ = Key{identityBar, 0, 0, dirIngress}
	mapKeyAllowFooL4 = Key{identityFoo, 80, 6, dirIngress}
	mapKeyAllow___L4 = Key{0, 80, 6, dirIngress}
	// Desired map entries for no L7 redirect / redirect to Proxy
	mapEntryL7None_ = MapStateEntry{l7RedirectNone_}
	mapEntryL7Proxy = MapStateEntry{l7RedirectProxy}
)

// combineL4L7 returns a new PortRule that refers to the specified l4 ports and
// l7 rules.
func combineL4L7(l4 []api.PortRule, l7 *api.L7Rules) []api.PortRule {
	result := make([]api.PortRule, len(l4))
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
	identityCache cache.IdentityCache
	log           io.Writer
}

func newPolicyDistillery(identities cache.IdentityCache) *policyDistillery {
	return &policyDistillery{
		Repository:    NewPolicyRepository(),
		identityCache: identities,
	}
}

func (d *policyDistillery) WithLogBuffer(w io.Writer) *policyDistillery {
	return &policyDistillery{
		Repository:    d.Repository,
		identityCache: d.identityCache,
		log:           w,
	}
}

// distillPolicy distills the policy repository into a set of bpf map state
// entries for an endpoint with the specified labels.
func (d *policyDistillery) distillPolicy(epLabels labels.LabelArray) (MapState, error) {
	result := make(MapState)

	endpointSelected, _ := d.Repository.GetRulesMatching(epLabels)
	io.WriteString(d.log, fmt.Sprintf("[distill] Endpoint selected by policy: %t\n", endpointSelected))

	// Prepare the L4 policy so we know whether L4 policy may apply
	ingressL4 := SearchContext{
		To:    epLabels,
		Trace: TRACE_VERBOSE,
	}
	ingressL4.Logging = logging.NewLogBackend(d.log, "", 0)
	io.WriteString(d.log, fmt.Sprintf("[distill] Evaluating L4 -> %s", epLabels))
	l4IngressPolicy, err := d.Repository.ResolveL4IngressPolicy(&ingressL4)
	if err != nil {
		return nil, err
	}

	// Handle L4 ingress from each identity in the cache to the endpoint.
	io.WriteString(d.log, "[distill] Producing L4 filter keys\n")
	for _, l4 := range *l4IngressPolicy {
		io.WriteString(d.log, fmt.Sprintf("[distill] Processing L4Filter (l3: %+v), (l4: %d/%s), (l7: %+v)\n", l4.Endpoints, l4.Port, l4.Protocol, l4.L7RulesPerEp))
		for _, key := range l4.ToKeys(0, d.identityCache) {
			io.WriteString(d.log, fmt.Sprintf("[distill] L4 ingress allow %+v (parser=%s, redirect=%t)\n", key, l4.L7Parser, l4.IsRedirect()))
			if l4.IsRedirect() {
				result[key] = MapStateEntry{l7RedirectProxy}
			} else {
				result[key] = MapStateEntry{l7RedirectNone_}
			}
		}
	}

	// Handle L3-wildcard of L7 destinations
	// Eg, when you have L4+L7 "allow /public on 80" with L3 "allow all from foo"
	// Initially, three keys would be generated: L4+L7, L3+L4+L7, and L3.
	// Here, we remove the L3+L4+L7 key if it overlaps with the L4+L7,
	// but only if they have the same L7 redirect.
	//
	// For these the BPF policy order of attempting L3+L4 lookup, L4 lookup,
	// then L3 lookup means that three keys are not strictly necessary; the
	// correct behaviour can be encoded with two keys - an L4 key and L3 key.
	nKeys := 0
	l3l4keys := make([]Key, len(result))
	for k := range result {
		if k.Identity > 0 && k.DestPort > 0 {
			l3l4keys[nKeys] = k
			nKeys++
		}
	}
	for i := 0; i < nKeys; i++ {
		k := l3l4keys[i]
		io.WriteString(d.log, fmt.Sprintf("[distill] Squashing L3-dependent L4 key %+v\n", k))
		wildcardL3 := Key{DestPort: k.DestPort, Nexthdr: k.Nexthdr, TrafficDirection: k.TrafficDirection}
		wildcardL4 := Key{Identity: k.Identity, TrafficDirection: k.TrafficDirection}
		if _, ok := result[wildcardL4]; ok {
			io.WriteString(d.log, fmt.Sprintf("[distill] -> Found L3 overlap %+v\n", wildcardL4))
			if entry, ok := result[wildcardL3]; ok {
				io.WriteString(d.log, fmt.Sprintf("[distill] -> Found L4 overlap %+v:%+v\n", wildcardL3, entry))
				if entry.ProxyPort == result[k].ProxyPort {
					io.WriteString(d.log, fmt.Sprintf("[distill] -> Removing L3-dependent L4 %+v\n", k))
					delete(result, k)
				}
			}
		}
	}

	return result, nil
}

func Test_MergeL3(t *testing.T) {
	identityCache := cache.IdentityCache{
		identity.NumericIdentity(identityFoo): labelsFoo,
		identity.NumericIdentity(identityBar): labelsBar,
	}

	tests := []struct {
		test   int
		rules  api.Rules
		result MapState
	}{
		{0, api.Rules{rule__L3AllowFoo, rule__L3AllowBar}, MapState{mapKeyAllowFoo__: mapEntryL7None_, mapKeyAllowBar__: mapEntryL7None_}},
		{1, api.Rules{rule__L3AllowFoo, ruleL3L4__Allow}, MapState{mapKeyAllowFoo__: mapEntryL7None_, mapKeyAllowFooL4: mapEntryL7None_}},
	}

	for _, tt := range tests {
		repo := newPolicyDistillery(identityCache)
		for _, r := range tt.rules {
			if r != nil {
				rule := r.WithEndpointSelector(selectFoo_)
				_, _ = repo.AddList(api.Rules{rule})
			}
		}
		t.Run(fmt.Sprintf("permutation_%d", tt.test), func(t *testing.T) {
			logBuffer := new(bytes.Buffer)
			repo = repo.WithLogBuffer(logBuffer)
			mapstate, err := repo.distillPolicy(labelsFoo)
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
		{1, api.Rules{rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFoo__: mapEntryL7None_}},
		{2, api.Rules{rule____NoAllow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7None_}},
		{3, api.Rules{rule____NoAllow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7None_, mapKeyAllowFoo__: mapEntryL7None_}},
		{4, api.Rules{rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7None_}},
		{5, api.Rules{rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7None_, mapKeyAllowFoo__: mapEntryL7None_}},
		{6, api.Rules{rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7None_}},                                    // Differs from spreadsheet(!)
		{7, api.Rules{rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7None_, mapKeyAllowFoo__: mapEntryL7None_}}, // Differs from spreadsheet(!)
		{8, api.Rules{rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy}},
		{9, api.Rules{rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy, mapKeyAllowFoo__: mapEntryL7None_}},
		{10, api.Rules{rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy}},
		{11, api.Rules{rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy, mapKeyAllowFoo__: mapEntryL7None_}},
		{12, api.Rules{rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy, mapKeyAllow___L4: mapEntryL7Proxy}},
		{13, api.Rules{rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy, mapKeyAllowFoo__: mapEntryL7None_}}, // Differs from spreadsheet(!)
		{14, api.Rules{rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy, mapKeyAllow___L4: mapEntryL7Proxy}},
		{15, api.Rules{rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy, mapKeyAllowFoo__: mapEntryL7None_}}, // Differs from spreadsheet(!)
		{16, api.Rules{ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy}},
		{17, api.Rules{ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy, mapKeyAllowFoo__: mapEntryL7None_}},
		// TODO: Tests 22-23 reveal a bug in the redirect logic (GH-7438).
		//{18, api.Rules{ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy, mapKeyAllow___L4: mapEntryL7None_}},
		//{19, api.Rules{ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy, mapKeyAllow___L4: mapEntryL7None_, mapKeyAllowFoo__: mapEntryL7None_}},
		{20, api.Rules{ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy}},
		{21, api.Rules{ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy, mapKeyAllowFoo__: mapEntryL7None_}},
		// TODO: Tests 22-23 reveal a bug in the redirect logic (GH-7438).
		//{22, api.Rules{ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy, mapKeyAllow___L4: mapEntryL7None_}},
		//{23, api.Rules{ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy, mapKeyAllow___L4: mapEntryL7None_, mapKeyAllowFoo__: mapEntryL7None_}},
		{24, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy, mapKeyAllow___L4: mapEntryL7Proxy}},
		{25, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy, mapKeyAllowFoo__: mapEntryL7None_}}, // Differs from spreadsheet(!)
		{26, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy, mapKeyAllow___L4: mapEntryL7Proxy}},
		{27, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy, mapKeyAllowFoo__: mapEntryL7None_}}, // Differs from spreadsheet(!)
		{28, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy, mapKeyAllow___L4: mapEntryL7Proxy}},
		{29, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy, mapKeyAllowFoo__: mapEntryL7None_}}, // Differs from spreadsheet(!)
		{30, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7Proxy, mapKeyAllow___L4: mapEntryL7Proxy}},
		{31, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllow___L4: mapEntryL7Proxy, mapKeyAllowFoo__: mapEntryL7None_}}, // Differs from spreadsheet(!)
	}
	for _, tt := range tests {
		repo := newPolicyDistillery(identityCache)
		for _, r := range tt.rules {
			if r != nil {
				rule := r.WithEndpointSelector(selectFoo_)
				_, _ = repo.AddList(api.Rules{rule})
			}
		}
		t.Run(fmt.Sprintf("permutation_%d", tt.test), func(t *testing.T) {
			logBuffer := new(bytes.Buffer)
			repo = repo.WithLogBuffer(logBuffer)
			mapstate, err := repo.distillPolicy(labelsFoo)
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
