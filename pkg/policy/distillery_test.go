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
	noIdentities__ = []uint32{}

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
)

// mapState is a helper function to create desired mapstate entries for each
// of the specified identities, where the key's port/proto/dir/l7 is the same.
func mapState(identities []uint32, port uint16, proto, dir uint8, l7 uint16) MapState {
	result := make(MapState)
	for _, id := range identities {
		key := Key{id, port, proto, dir}
		result[key] = MapStateEntry{l7}
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
	io.WriteString(d.log, fmt.Sprintf("[test] Endpoint selected by policy: %t\n", endpointSelected))

	// Prepare the L4 policy so we know whether L4 policy may apply
	ingressL4 := SearchContext{
		To:    epLabels,
		Trace: TRACE_VERBOSE,
	}
	ingressL4.Logging = logging.NewLogBackend(d.log, "", 0)
	io.WriteString(d.log, fmt.Sprintf("[test] Evaluating L4 -> %s", epLabels))
	l4IngressPolicy, err := d.Repository.ResolveL4IngressPolicy(&ingressL4)
	if err != nil {
		return nil, err
	}

	// Handle L3 ingress from each identity in the cache to the endpoint.
	// Build a cache of requirements that are used for l4 policy resolution.
	deniedPeers := make(cache.IdentityCache)
	for id, lbls := range d.identityCache {
		io.WriteString(d.log, fmt.Sprintf("[test] Evaluating %s -> %s\n", lbls, epLabels))
		ingressL3 := &SearchContext{
			From:  lbls,
			To:    epLabels,
			Trace: TRACE_VERBOSE,
		}
		ingressL3.Logging = logging.NewLogBackend(d.log, "", 0)

		switch d.Repository.CanReachIngressRLocked(ingressL3) {
		case api.Allowed:
			key := Key{uint32(id), 0, 0, dirIngress}
			result[key] = MapStateEntry{l7RedirectNone_}
		case api.Undecided:
			// If there's no L4 policy, undecided becomes allow.
			if len(*l4IngressPolicy) == 0 && !endpointSelected {
				key := Key{uint32(id), 0, 0, dirIngress}
				result[key] = MapStateEntry{l7RedirectNone_}
			}
			// Otherwise this will be handled in L4 resolution below.
		case api.Denied:
			deniedPeers[id] = lbls
		}
	}

	// Handle L4 ingress from each identity in the cache to the endpoint.
	io.WriteString(d.log, "[test] Producing L4 filter keys\n")
	for _, l4 := range *l4IngressPolicy {
		for _, key := range l4.ToKeys(0, d.identityCache, deniedPeers) {
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

	return result, nil
}

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

type testCase struct {
	test      int
	selector  api.EndpointSelector
	l3        api.EndpointSelector
	l4        []api.PortRule
	l7        *api.L7Rules
	fooResult MapState
	barResult MapState
	bazResult MapState
}

func (tt *testCase) String() string {
	return fmt.Sprintf("Test %d: Select %q;\nl3: %q;\nl4: \"%v;\"\nl7: \"%v\"\n",
		tt.test, tt.selector.LabelSelectorString(), tt.l3.LabelSelectorString(), tt.l4, tt.l7)
}

func Test_SingleRuleKeyGeneration(t *testing.T) {
	identityCache := cache.IdentityCache{
		identity.NumericIdentity(identityFoo): labelsFoo,
		identity.NumericIdentity(identityBar): labelsBar,
		identity.NumericIdentity(identityBaz): labelsBaz,
	}
	tests := []testCase{
		// Allow-all rules with different selectors.
		// Select      | L3 allow   | L4 allow   | L7 allow     | Desired map state (endpoint foo)                           | Desired map state (endpoint bar)                           | Desired map state (endpoint baz)
		{0, selectAny_, allowAllL3_, allowAllL4_, allowAllL7___, mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_)},
		{1, selectFoo_, allowAllL3_, allowAllL4_, allowAllL7___, mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_)},
		{2, selectBlue, allowAllL3_, allowAllL4_, allowAllL7___, mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_)},
		{3, selectBar_, allowAllL3_, allowAllL4_, allowAllL7___, mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_)},
		{4, selectBaz_, allowAllL3_, allowAllL4_, allowAllL7___, mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_)},
		{5, selectNone, allowAllL3_, allowAllL4_, allowAllL7___, mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_)},
		// Allow only ingress from Red.
		{6, selectAny_, allowRedL3_, allowAllL4_, allowAllL7___, mapState(redIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(redIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(redIdentities_, 0, 0, dirIngress, l7RedirectNone_)},
		{7, selectFoo_, allowRedL3_, allowAllL4_, allowAllL7___, mapState(redIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_)},
		{8, selectBlue, allowRedL3_, allowAllL4_, allowAllL7___, mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(redIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(redIdentities_, 0, 0, dirIngress, l7RedirectNone_)},
		{9, selectBar_, allowRedL3_, allowAllL4_, allowAllL7___, mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(redIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_)},
		{10, selectBaz_, allowRedL3_, allowAllL4_, allowAllL7___, mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(redIdentities_, 0, 0, dirIngress, l7RedirectNone_)},
		{11, selectNone, allowRedL3_, allowAllL4_, allowAllL7___, mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_)},
		// Allow only ingress from Foo.
		// Select       | L3 allow   | L4 allow   | L7 allow     | Desired map state (endpoint foo)                           | Desired map state (endpoint bar)                           | Desired map state (endpoint baz)
		{12, selectAny_, allowFooL3_, allowAllL4_, allowAllL7___, mapState(fooIdentity___, 0, 0, dirIngress, l7RedirectNone_), mapState(fooIdentity___, 0, 0, dirIngress, l7RedirectNone_), mapState(fooIdentity___, 0, 0, dirIngress, l7RedirectNone_)},
		{13, selectFoo_, allowFooL3_, allowAllL4_, allowAllL7___, mapState(fooIdentity___, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_)},
		{14, selectBlue, allowFooL3_, allowAllL4_, allowAllL7___, mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(fooIdentity___, 0, 0, dirIngress, l7RedirectNone_), mapState(fooIdentity___, 0, 0, dirIngress, l7RedirectNone_)},
		{15, selectBar_, allowFooL3_, allowAllL4_, allowAllL7___, mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(fooIdentity___, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_)},
		{16, selectBaz_, allowFooL3_, allowAllL4_, allowAllL7___, mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(fooIdentity___, 0, 0, dirIngress, l7RedirectNone_)},
		{17, selectNone, allowFooL3_, allowAllL4_, allowAllL7___, mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_)},

		// ...
		// Select       | L3 allow   | L4 allow   | L7 allow     | Desired map state (endpoint foo)                           | Desired map state (endpoint bar)                           | Desired map state (endpoint baz)
		{18, selectAny_, allowAllL3_, allowPort80, allowHTTPRoot, mapState(allIdentities_, 80, 6, dirIngress, l7RedirectHTTP_), mapState(allIdentities_, 80, 6, dirIngress, l7RedirectHTTP_), mapState(allIdentities_, 80, 6, dirIngress, l7RedirectHTTP_)},
		{19, selectFoo_, allowAllL3_, allowPort80, allowHTTPRoot, mapState(allIdentities_, 80, 6, dirIngress, l7RedirectHTTP_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_)},
		{20, selectBlue, allowAllL3_, allowPort80, allowHTTPRoot, mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 80, 6, dirIngress, l7RedirectHTTP_), mapState(allIdentities_, 80, 6, dirIngress, l7RedirectHTTP_)},
		{21, selectBar_, allowAllL3_, allowPort80, allowHTTPRoot, mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 80, 6, dirIngress, l7RedirectHTTP_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_)},
		{22, selectBaz_, allowAllL3_, allowPort80, allowHTTPRoot, mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 80, 6, dirIngress, l7RedirectHTTP_)},
		{23, selectNone, allowAllL3_, allowPort80, allowHTTPRoot, mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_), mapState(allIdentities_, 0, 0, dirIngress, l7RedirectNone_)},
	}
	for _, tt := range tests {
		t.Run(tt.String(), func(t *testing.T) {
			repo := newPolicyDistillery(identityCache)
			rule := api.NewRule().
				WithEndpointSelector(tt.selector).
				WithIngressRules([]api.IngressRule{{
					FromEndpoints: []api.EndpointSelector{tt.l3},
					ToPorts:       combineL4L7(tt.l4, tt.l7),
				}})
			_ = repo.AddList(api.Rules{rule})

			endpoints := []struct {
				labels labels.LabelArray
				result MapState
			}{
				{labelsFoo, tt.fooResult},
				{labelsBar, tt.barResult},
				{labelsBaz, tt.bazResult},
			}

			for _, ep := range endpoints {
				logBuffer := new(bytes.Buffer)
				repo = repo.WithLogBuffer(logBuffer)
				mapstate, err := repo.distillPolicy(ep.labels)
				if err != nil {
					t.Errorf("Policy resolution failure: %s", err)
				}
				if equal, err := checker.DeepEqual(mapstate, ep.result); !equal {
					t.Errorf("Policy Trace: \n%s\n======= ERROR =======\nPolicy obtained didn't match expected for endpoint %s:\n%s", logBuffer.String(), ep.labels, err)
				}
			}
		})
	}
}
