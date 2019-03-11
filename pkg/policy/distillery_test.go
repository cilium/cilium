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
	// Endpoints - "foo" is red, "bar" and "baz" are "blue".
	identityFoo = uint32(100)
	labelsFoo   = labels.ParseSelectLabelArray("foo", "red")
	identityBar = uint32(200)
	labelsBar   = labels.ParseSelectLabelArray("bar", "blue")
	identityBaz = uint32(201)
	labelsBaz   = labels.ParseSelectLabelArray("baz", "blue")

	// Identity slices for different combinations of the above endpoints
	allIdentities_ = []uint32{identityFoo, identityBar, identityBaz}
	redIdentities_ = []uint32{identityFoo}
	fooIdentity___ = []uint32{identityFoo}
	blueIdentities = []uint32{identityBar, identityBaz}
	barIdentity___ = []uint32{identityBar}
	bazIdentity___ = []uint32{identityBaz}
	noIdentities__ []uint32

	// Selectors for different combinations of the above endpoints
	selectAny_ = api.WildcardEndpointSelector
	selectRed_ = api.NewESFromLabels(labels.ParseSelectLabel("red"))
	selectBlue = api.NewESFromLabels(labels.ParseSelectLabel("blue"))
	selectFoo_ = api.NewESFromLabels(labels.ParseSelectLabel("foo"))
	selectBar_ = api.NewESFromLabels(labels.ParseSelectLabel("bar"))
	selectBaz_ = api.NewESFromLabels(labels.ParseSelectLabel("baz"))
	selectNone = api.NoEndpointSelector

	// Same as the above selectors, but with better naming for rules
	allowAllL3_ = selectAny_
	allowRedL3_ = selectRed_
	allowBlueL3 = selectBlue
	allowFooL3_ = selectFoo_
	allowBarL3_ = selectBar_
	allowBazL3_ = selectBaz_
	allowNoL3__ = selectNone

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
	allowKafkaFoo = &api.L7Rules{
		Kafka: []api.PortRuleKafka{
			{Topic: "foo"},
		},
		L7Proto: ParserTypeKafka.String(),
	}

	// Misc other bpf key fields for convenience / readability.
	l7RedirectNone_ = uint16(0)
	l7RedirectHTTP_ = uint16(1)
	l7RedirectKafka = uint16(2)
	l7RedirectDNS__ = uint16(3)
	dirIngress      = trafficdirection.Ingress.Uint8()

	// API rules for disallow, L3, L3L4, L3L4L7, L4, L4L7
	rule____NoAllow = api.NewRule().
			WithIngressRules([]api.IngressRule{api.IngressRule{}})
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

	// BPF map keys
	mapKeyAllowFoo__ = Key{identityFoo, 0, 0, dirIngress}
	mapKeyAllowFooL4 = Key{identityFoo, 80, 6, dirIngress}
	mapKeyAllow___L4 = Key{0, 80, 6, dirIngress}
	mapEntryL7None_  = MapStateEntry{l7RedirectNone_}
	mapEntryL7HTTP_  = MapStateEntry{l7RedirectHTTP_}
)

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
// entries for the specified endpoint labels.
func (d *policyDistillery) distillPolicy(epLabels labels.LabelArray) (MapState, error) {
	result := make(MapState)

	endpointSelected, _, _ := d.Repository.getMatchingRules(epLabels)
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

	// Handle L3 ingress from each identity in the cache to the endpoint.
	// Build a cache of requirements that are used for l4 policy resolution.
	deniedPeers := make(cache.IdentityCache)
	for id, lbls := range d.identityCache {
		io.WriteString(d.log, fmt.Sprintf("[distill] Evaluating %s -> %s\n", lbls, epLabels))
		ingressL3 := &SearchContext{
			From:  lbls,
			To:    epLabels,
			Trace: TRACE_VERBOSE,
		}
		ingressL3.Logging = logging.NewLogBackend(d.log, "", 0)

		switch d.Repository.CanReachIngressRLocked(ingressL3) {
		case api.Allowed:
			io.WriteString(d.log, "[distill] L3 ingress allow\n")
			key := Key{uint32(id), 0, 0, dirIngress}
			result[key] = MapStateEntry{l7RedirectNone_}
		case api.Undecided:
			io.WriteString(d.log, "[distill] L3 ingress undecided\n")
			// If there's no L4 policy, undecided becomes allow.
			if len(*l4IngressPolicy) == 0 && !endpointSelected {
				key := Key{uint32(id), 0, 0, dirIngress}
				result[key] = MapStateEntry{l7RedirectNone_}
				io.WriteString(d.log, "[distill] Endpoint not selected; allowing\n")
			}
			// Otherwise this will be handled in L4 resolution below.
		case api.Denied:
			io.WriteString(d.log, "[distill] L3 ingress denied\n")
			deniedPeers[id] = lbls
		}
	}

	// Handle L4 ingress from each identity in the cache to the endpoint.
	io.WriteString(d.log, "[distill] Producing L4 filter keys\n")
	for _, l4 := range *l4IngressPolicy {
		io.WriteString(d.log, fmt.Sprintf("[distill] Processing L4Filter (l7: %+v)\n", l4.L7RulesPerEp))
		for _, key := range l4.ToKeys(0, d.identityCache, deniedPeers) {
			io.WriteString(d.log, fmt.Sprintf("[distill] L4 ingress allow %+v (parser=%s, redirect=%t)\n", key, l4.L7Parser, l4.IsRedirect()))
			switch l4.L7Parser {
			case ParserTypeHTTP:
				result[key] = MapStateEntry{l7RedirectHTTP_}
			case ParserTypeKafka:
				result[key] = MapStateEntry{l7RedirectKafka}
			case ParserTypeDNS:
				result[key] = MapStateEntry{l7RedirectDNS__}
			default:
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

func Test_MergeRules(t *testing.T) {
	identityCache := cache.IdentityCache{
		identity.NumericIdentity(identityFoo): labelsFoo,
	}

	tests := []struct {
		test   int
		rules  api.Rules
		result MapState
	}{
		// Allow-all rules with different selectors.
		{0, api.Rules{rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, MapState{}},
		{1, api.Rules{rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFoo__: mapEntryL7None_}},
		{2, api.Rules{rule____NoAllow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7None_}},                                    // Differs from spreadsheet(!)
		{3, api.Rules{rule____NoAllow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7None_, mapKeyAllowFoo__: mapEntryL7None_}}, // Differs from spreadsheet(!)
		{4, api.Rules{rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7None_}},
		{5, api.Rules{rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7None_, mapKeyAllowFoo__: mapEntryL7None_}},
		{6, api.Rules{rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7None_}},                                     // Differs from spreadsheet(!)
		{7, api.Rules{rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7None_, mapKeyAllowFoo__: mapEntryL7None_}},  // Differs from spreadsheet(!)
		{8, api.Rules{rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_}},                                     // Differs from spreadsheet(!)
		{9, api.Rules{rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_, mapKeyAllowFoo__: mapEntryL7None_}},  // Differs from spreadsheet(!)
		{10, api.Rules{rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_}},                                    // Differs from spreadsheet(!)
		{11, api.Rules{rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_, mapKeyAllowFoo__: mapEntryL7None_}}, // Differs from spreadsheet(!)
		{12, api.Rules{rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_}},                                    // Differs from spreadsheet(!)
		{13, api.Rules{rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_, mapKeyAllowFoo__: mapEntryL7None_}}, // Differs from spreadsheet(!)
		{14, api.Rules{rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_}},                                    // Differs from spreadsheet(!)
		{15, api.Rules{rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_, mapKeyAllowFoo__: mapEntryL7None_}}, // Differs from spreadsheet(!)
		{16, api.Rules{ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_}},
		{17, api.Rules{ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_, mapKeyAllowFoo__: mapEntryL7None_}},
		// TODO: Tests 22-23 reveal a bug in the redirect logic (GH-7438).
		//{18, api.Rules{ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_, mapKeyAllow___L4: mapEntryL7None_}},
		//{19, api.Rules{ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_, mapKeyAllow___L4: mapEntryL7None_, mapKeyAllowFoo__: mapEntryL7None_}},
		{20, api.Rules{ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_}},
		{21, api.Rules{ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_, mapKeyAllowFoo__: mapEntryL7None_}},
		// TODO: Tests 22-23 reveal a bug in the redirect logic (GH-7438).
		//{22, api.Rules{ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_, mapKeyAllow___L4: mapEntryL7None_}},
		//{23, api.Rules{ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_, mapKeyAllow___L4: mapEntryL7None_, mapKeyAllowFoo__: mapEntryL7None_}},
		{24, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_}},                                    // Differs from spreadsheet(!)
		{25, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_, mapKeyAllowFoo__: mapEntryL7None_}}, // Differs from spreadsheet(!)
		{26, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_}},                                    // Differs from spreadsheet(!)
		{27, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_, mapKeyAllowFoo__: mapEntryL7None_}}, // Differs from spreadsheet(!)
		{28, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_}},                                    // Differs from spreadsheet(!)
		{29, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_, mapKeyAllowFoo__: mapEntryL7None_}}, // Differs from spreadsheet(!)
		{30, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_}},                                    // Differs from spreadsheet(!)
		{31, api.Rules{ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, MapState{mapKeyAllowFooL4: mapEntryL7HTTP_, mapKeyAllowFoo__: mapEntryL7None_}}, // Differs from spreadsheet(!)
	}
	for _, tt := range tests {
		repo := newPolicyDistillery(identityCache)
		for _, r := range tt.rules {
			if r != nil {
				rule := r.WithEndpointSelector(selectFoo_)
				_ = repo.AddList(api.Rules{rule})
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
