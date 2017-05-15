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
	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (ds *PolicyTestSuite) TestConsumerAllows(c *C) {
	ctx := SearchContext{From: labels.LabelArray{
		labels.NewLabel("1", "1", "1"),
		labels.NewLabel("2", "2", "2"),
		labels.NewLabel("3", "3", "3"),
	}}

	rule1 := AllowRule{
		Action: api.ALWAYS_ACCEPT,
		Labels: labels.LabelArray{
			labels.NewLabel("1", "1", "1"),
			labels.NewLabel("2", "2", "2"),
		},
	}
	rule2 := AllowRule{
		Action: api.ALWAYS_ACCEPT,
		Labels: labels.LabelArray{
			labels.NewLabel("3", "3", "3"),
			labels.NewLabel("4", "4", "4"),
		},
	}

	c.Assert(rule1.Allows(&ctx), Equals, api.ALWAYS_ACCEPT)
	c.Assert(rule2.Allows(&ctx), Equals, api.UNDECIDED)
}

func (ds *PolicyTestSuite) TestK8sRule(c *C) {
	ctx := SearchContext{
		Trace: TRACE_VERBOSE,
		From: labels.LabelArray{
			labels.NewLabel("k8s.role", "frontend", k8s.LabelSource),
		},
		To: labels.LabelArray{
			labels.NewLabel("root.k8s.role", "backend", k8s.LabelSource),
		},
	}

	rule1 := &AllowRule{
		Action: api.ALWAYS_ACCEPT,
		Labels: labels.LabelArray{
			labels.NewLabel("k8s.role", "frontend", k8s.LabelSource),
		},
	}

	k8sRule := RuleConsumers{
		RuleBase: RuleBase{
			CoverageSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"role": "backend",
				},
			},
		},
		Allow: []*AllowRule{rule1},
	}

	c.Assert(k8sRule.Allows(&ctx), Equals, api.ALWAYS_ACCEPT)
}
