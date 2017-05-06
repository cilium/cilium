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

package policy

import (
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/labels"

	. "gopkg.in/check.v1"
)

func (s *PolicyTestSuite) TestGetL4Policy(c *C) {
	// -> [bar]
	toBar := SearchContext{
		To: []*labels.Label{
			labels.NewLabel("root.bar", "", common.CiliumLabelSource),
		},
	}

	// -> [foo]
	toFoo := SearchContext{
		To: []*labels.Label{
			labels.NewLabel("root.foo", "", common.CiliumLabelSource),
		},
	}

	// -> [bar, baz]
	toBarBaz := SearchContext{
		To: []*labels.Label{
			labels.NewLabel("root.bar", "", common.CiliumLabelSource),
			labels.NewLabel("root.baz", "", common.CiliumLabelSource),
		},
	}

	http1 := L4Filter{Port: 80, Protocol: "tcp"}
	http2 := L4Filter{Port: 8080, Protocol: "tcp"}

	filterIngressHTTP := AllowL4{
		Ingress: []L4Filter{http1, http2},
		Egress:  []L4Filter{},
	}

	filterEgressHTTP := AllowL4{
		Ingress: []L4Filter{},
		Egress:  []L4Filter{http1, http2},
	}

	filterIngressEgressHTTP := AllowL4{
		Ingress: []L4Filter{http1, http2},
		Egress:  []L4Filter{http1, http2},
	}

	// coverage: [Bar], allow: ingressHTTP
	ruleBarIngressHTTP := RuleL4{
		RuleBase{[]*labels.Label{labels.NewLabel("root.bar", "", common.CiliumLabelSource)}},
		[]AllowL4{filterIngressHTTP},
	}

	expected := NewL4Policy()
	expected.Ingress["tcp:80"] = http1
	expected.Ingress["tcp:8080"] = http2

	c.Assert(*ruleBarIngressHTTP.GetL4Policy(&toBar, NewL4Policy()), DeepEquals, *expected)
	c.Assert(ruleBarIngressHTTP.GetL4Policy(&toFoo, NewL4Policy()), IsNil)
	c.Assert(*ruleBarIngressHTTP.GetL4Policy(&toBarBaz, NewL4Policy()), DeepEquals, *expected)

	// coverage: [bar], allow: egressHTTP
	ruleBarEgressHTTP := RuleL4{
		RuleBase{[]*labels.Label{labels.NewLabel("root.bar", "", common.CiliumLabelSource)}},
		[]AllowL4{filterEgressHTTP},
	}

	expected = NewL4Policy()
	expected.Egress["tcp:80"] = http1
	expected.Egress["tcp:8080"] = http2

	c.Assert(*ruleBarEgressHTTP.GetL4Policy(&toBar, NewL4Policy()), DeepEquals, *expected)
	c.Assert(ruleBarEgressHTTP.GetL4Policy(&toFoo, NewL4Policy()), IsNil)
	c.Assert(*ruleBarEgressHTTP.GetL4Policy(&toBarBaz, NewL4Policy()), DeepEquals, *expected)

	// coverage: [Bar], allow: ingressHTTP, egressHTTP
	ruleBarIngressEgressHTTP := RuleL4{
		RuleBase{[]*labels.Label{labels.NewLabel("root.bar", "", common.CiliumLabelSource)}},
		[]AllowL4{filterIngressEgressHTTP},
	}

	expected = NewL4Policy()
	expected.Ingress["tcp:80"] = http1
	expected.Ingress["tcp:8080"] = http2
	expected.Egress["tcp:80"] = http1
	expected.Egress["tcp:8080"] = http2

	c.Assert(*ruleBarIngressEgressHTTP.GetL4Policy(&toBar, NewL4Policy()), DeepEquals, *expected)
	c.Assert(ruleBarIngressEgressHTTP.GetL4Policy(&toFoo, NewL4Policy()), IsNil)
	c.Assert(*ruleBarIngressEgressHTTP.GetL4Policy(&toBarBaz, NewL4Policy()), DeepEquals, *expected)

	filter90To92 := AllowL4{
		Ingress: []L4Filter{
			{Port: 90},
			{Port: 91},
			{Port: 92},
		},
		Egress: []L4Filter{
			{Port: 90},
			{Port: 91},
			{Port: 92},
		},
	}

	rule2 := RuleL4{
		Allow: []AllowL4{filter90To92},
	}

	rootNode := Node{
		Name:  RootNodeName,
		Rules: []PolicyRule{&ruleBarEgressHTTP},
		Children: map[string]*Node{
			"foo": {},
			"bar": {
				Rules: []PolicyRule{&rule2},
			},
		},
	}

	c.Assert(rootNode.ResolveTree(), Equals, nil)
}
