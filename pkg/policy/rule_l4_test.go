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
	lblFoo := labels.NewLabel("root.foo", "", common.CiliumLabelSource)
	lblBar := labels.NewLabel("root.bar", "", common.CiliumLabelSource)
	lblBaz := labels.NewLabel("root.baz", "", common.CiliumLabelSource)

	// -> [Foo]
	toFoo := SearchContext{To: []*labels.Label{lblFoo}}

	// -> [Baz, Bar]
	toBazBar := SearchContext{To: []*labels.Label{lblBaz, lblBar}}

	http1 := L4Filter{Port: 80, Protocol: "tcp"}
	http2 := L4Filter{Port: 8080, Protocol: "tcp"}

	filterHttp := AllowL4{
		Ingress: []L4Filter{http1, http2},
		Egress:  []L4Filter{},
	}

	filter90To92 := AllowL4{
		Ingress: []L4Filter{
			{Port: 90},
			{Port: 91},
			{Port: 92},
		},
		Egress: []L4Filter{},
	}

	rule1 := RuleL4{
		Coverage: []*labels.Label{lblBar},
		Allow:    []AllowL4{filterHttp},
	}

	res := NewL4Policy()
	c.Assert(rule1.GetL4Policy(&toFoo, res), IsNil)

	expected := NewL4Policy()
	expected.Ingress["tcp:80"] = http1
	expected.Ingress["tcp:8080"] = http2

	res = NewL4Policy()
	c.Assert(*rule1.GetL4Policy(&toBazBar, res), DeepEquals, *expected)

	rule2 := RuleL4{
		Allow: []AllowL4{filter90To92},
	}

	rootNode := Node{
		Name:  RootNodeName,
		Rules: []PolicyRule{&rule1},
		Children: map[string]*Node{
			"foo": {},
			"bar": {
				Rules: []PolicyRule{&rule2},
			},
		},
	}

	c.Assert(rootNode.ResolveTree(), Equals, nil)
}
