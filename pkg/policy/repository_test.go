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
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
)

func (ds *PolicyTestSuite) TestAddSearchDelete(c *C) {
	repo := NewPolicyRepository()

	// cannot add empty rule
	c.Assert(repo.Add(api.Rule{}), Not(IsNil))

	lbls1 := labels.LabelArray{
		labels.ParseLabel("tag1"),
		labels.ParseLabel("tag2"),
	}
	rule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("foo")),
		Labels:           lbls1,
	}
	rule2 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Labels:           lbls1,
	}
	lbls2 := labels.LabelArray{labels.ParseSelectLabel("tag3")}
	rule3 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Labels:           lbls2,
	}

	// add rule1,rule2
	c.Assert(repo.Add(rule1), IsNil)
	c.Assert(repo.Add(rule2), IsNil)

	// rule3 should not be in there yet
	repo.Mutex.RLock()
	c.Assert(repo.SearchRLocked(lbls2), DeepEquals, api.Rules{})
	repo.Mutex.RUnlock()

	// add rule3
	c.Assert(repo.Add(rule3), IsNil)

	// search rule1,rule2
	repo.Mutex.RLock()
	c.Assert(repo.SearchRLocked(lbls1), DeepEquals, api.Rules{&rule1, &rule2})
	c.Assert(repo.SearchRLocked(lbls2), DeepEquals, api.Rules{&rule3})
	repo.Mutex.RUnlock()

	// delete rule1, rule2
	c.Assert(repo.DeleteByLabels(lbls1), Equals, 2)
	// delete rule1, rule2 again has no effect
	c.Assert(repo.DeleteByLabels(lbls1), Equals, 0)

	// rule3 can still be found
	repo.Mutex.RLock()
	c.Assert(repo.SearchRLocked(lbls2), DeepEquals, api.Rules{&rule3})
	repo.Mutex.RUnlock()

	// delete rule3
	c.Assert(repo.DeleteByLabels(lbls2), Equals, 1)

	// rule1 is gone
	repo.Mutex.RLock()
	c.Assert(repo.SearchRLocked(lbls2), DeepEquals, api.Rules{})
	repo.Mutex.RUnlock()

}

func (ds *PolicyTestSuite) TestCanReach(c *C) {
	repo := NewPolicyRepository()

	fooToBar := &SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar"),
	}

	repo.Mutex.RLock()
	// no rules loaded: CanReach => undecided
	c.Assert(repo.CanReachRLocked(fooToBar), Equals, api.Undecided)
	// no rules loaded: Allows() => denied
	c.Assert(repo.AllowsRLocked(fooToBar), Equals, api.Denied)
	repo.Mutex.RUnlock()

	tag1 := labels.LabelArray{labels.ParseLabel("tag1")}
	rule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(labels.ParseSelectLabel("foo")),
				},
			},
		},
		Labels: tag1,
	}

	// selector: groupA
	// require: groupA
	rule2 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("groupA")),
		Ingress: []api.IngressRule{
			{
				FromRequires: []api.EndpointSelector{
					api.NewESFromLabels(labels.ParseSelectLabel("groupA")),
				},
			},
		},
		Labels: tag1,
	}
	rule3 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar2")),
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(labels.ParseSelectLabel("foo")),
				},
			},
		},
		Labels: tag1,
	}

	c.Assert(repo.Add(rule1), IsNil)
	c.Assert(repo.Add(rule2), IsNil)
	c.Assert(repo.Add(rule3), IsNil)

	// foo=>bar is OK
	c.Assert(repo.AllowsRLocked(fooToBar), Equals, api.Allowed)

	// foo=>bar2 is OK
	c.Assert(repo.AllowsRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar2"),
	}), Equals, api.Allowed)

	// foo=>bar inside groupA is OK
	c.Assert(repo.AllowsRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupA"),
		To:   labels.ParseSelectLabelArray("bar", "groupA"),
	}), Equals, api.Allowed)

	// groupB can't talk to groupA => Denied
	c.Assert(repo.AllowsRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupB"),
		To:   labels.ParseSelectLabelArray("bar", "groupA"),
	}), Equals, api.Denied)

	// no restriction on groupB, unused label => OK
	c.Assert(repo.AllowsRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupB"),
		To:   labels.ParseSelectLabelArray("bar", "groupB"),
	}), Equals, api.Allowed)

	// foo=>bar3, no rule => Denied
	c.Assert(repo.AllowsRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar3"),
	}), Equals, api.Denied)
}
